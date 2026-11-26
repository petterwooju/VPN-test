// Package packetproxy forwards claimed IP traffic into one selected encrypted
// proxy. It has no OS-level direct dialer.
package packetproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	SupportsUDP() bool
	Close()
}

var ErrUnsupported = errors.New("unsupported IP transport")
var ErrBuffer = errors.New("packet buffer too small")

type Plane struct {
	leaf      Dialer
	system    *stack.Stack
	link      *channel.Endpoint
	life      context.Context
	cancel    context.CancelFunc
	slots     chan struct{}
	closeOnce sync.Once
	injectMu  sync.RWMutex
}

func New(leaf Dialer) (*Plane, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	const nic = 1
	link := channel.New(128, 1280, "")
	if err := s.CreateNIC(nic, link); err != nil {
		s.Close()
		return nil, errors.New(err.String())
	}
	if err := s.SetPromiscuousMode(nic, true); err != nil {
		s.Close()
		return nil, errors.New(err.String())
	}
	if err := s.SetSpoofing(nic, true); err != nil {
		s.Close()
		return nil, errors.New(err.String())
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nic},
		{Destination: header.IPv6EmptySubnet, NIC: nic},
	})
	ctx, cancel := context.WithCancel(context.Background())
	p := &Plane{leaf: leaf, system: s, link: link, life: ctx, cancel: cancel, slots: make(chan struct{}, 128)}
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, 0, 64, p.forwardTCP).HandlePacket)
	if leaf.SupportsUDP() {
		s.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(s, p.forwardUDP).HandlePacket)
	}
	return p, nil
}

func (p *Plane) Lifetime() context.Context { return p.life }

func (p *Plane) Close() {
	p.closeOnce.Do(func() {
		p.cancel()
		p.leaf.Close()
		p.injectMu.Lock()
		p.system.Close()
		p.link.Close()
		p.injectMu.Unlock()
		p.system.Wait()
	})
}

func inspect(ip []byte) (tcpip.NetworkProtocolNumber, byte, bool) {
	if len(ip) < 20 || len(ip) > 65535 {
		return 0, 0, false
	}
	if ip[0]>>4 == 4 {
		h := int(ip[0]&15) * 4
		if h < 20 || h > len(ip) || int(binary.BigEndian.Uint16(ip[2:4])) != len(ip) {
			return 0, 0, false
		}
		return ipv4.ProtocolNumber, ip[9], true
	}
	if ip[0]>>4 != 6 || len(ip) < 40 || int(binary.BigEndian.Uint16(ip[4:6])) != len(ip)-40 {
		return 0, 0, false
	}
	next, off := ip[6], 40
	// Walk extension headers to determine the terminal IP transport before dispatch.
	for i := 0; i < 8; i++ {
		if next == 6 || next == 17 {
			return ipv6.ProtocolNumber, next, true
		}
		if off+2 > len(ip) {
			return 0, 0, false
		}
		var size int
		switch next {
		case 0, 43, 60:
			size = (int(ip[off+1]) + 1) * 8
		case 44:
			size = 8
		case 51:
			size = (int(ip[off+1]) + 2) * 4
		default:
			return 0, 0, false
		}
		if off+size > len(ip) {
			return 0, 0, false
		}
		next, off = ip[off], off+size
	}
	return 0, 0, false
}

func (p *Plane) Write(ip []byte) error {
	family, protocol, ok := inspect(ip)
	if !ok || (protocol != 6 && (protocol != 17 || !p.leaf.SupportsUDP())) {
		return ErrUnsupported
	}
	p.injectMu.RLock()
	defer p.injectMu.RUnlock()
	if p.life.Err() != nil {
		return net.ErrClosed
	}
	// packetFlow owns the caller's memory only for this call; gVisor may retain it.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), ip...))})
	defer pkt.DecRef()
	p.link.InjectInbound(family, pkt)
	return nil
}

func (p *Plane) Read(out []byte, timeout time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(p.life, timeout)
	defer cancel()
	pkt := p.link.ReadContext(ctx)
	if pkt == nil {
		if p.life.Err() != nil {
			return 0, net.ErrClosed
		}
		return 0, nil
	}
	defer pkt.DecRef()
	if pkt.Size() > len(out) {
		return 0, ErrBuffer
	}
	n := 0
	for _, part := range pkt.AsSlices() {
		n += copy(out[n:], part)
	}
	return n, nil
}

func (p *Plane) reserve() bool {
	if p.life.Err() != nil {
		return false
	}
	select {
	case p.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func destination(id stack.TransportEndpointID) string {
	return net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
}

func (p *Plane) dial(network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(p.life, 10*time.Second)
	defer cancel()
	return p.leaf.DialContext(ctx, network, address)
}

func (p *Plane) forwardTCP(r *tcp.ForwarderRequest) {
	if !p.reserve() {
		r.Complete(true)
		return
	}
	defer func() { <-p.slots }()
	peer, err := p.dial("tcp", destination(r.ID()))
	if err != nil {
		r.Complete(true)
		return
	}
	defer peer.Close()
	stop := context.AfterFunc(p.life, func() { _ = peer.Close() })
	defer stop()
	var q waiter.Queue
	ep, e := r.CreateEndpoint(&q)
	r.Complete(e != nil)
	if e != nil {
		return
	}
	local := gonet.NewTCPConn(&q, ep)
	defer local.Close()
	interrupted := context.AfterFunc(p.life, func() { _ = local.Close() })
	defer interrupted()

	done := make(chan struct{}, 2)
	pump := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if half, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		done <- struct{}{}
	}
	go pump(peer, local)
	go pump(local, peer)
	<-done
	// Allow a response after half-close, while bounding transports without half-close.
	_ = local.SetDeadline(time.Now().Add(30 * time.Second))
	_ = peer.SetDeadline(time.Now().Add(30 * time.Second))
	<-done
}

func (p *Plane) forwardUDP(r *udp.ForwarderRequest) bool {
	if !p.reserve() {
		return true
	}
	address := destination(r.ID())
	var q waiter.Queue
	// Register immediately while the first datagram still belongs to the forwarder.
	ep, e := r.CreateEndpoint(&q)
	if e != nil {
		<-p.slots
		return true
	}
	local := gonet.NewUDPConn(&q, ep)
	go func() {
		defer func() { <-p.slots }()
		defer local.Close()
		peer, err := p.dial("udp", address)
		if err != nil {
			return
		}
		defer peer.Close()
		var once sync.Once
		closeBoth := func() { once.Do(func() { _ = peer.Close(); _ = local.Close() }) }
		interrupted := context.AfterFunc(p.life, closeBoth)
		defer interrupted()
		updateIdle := func() {
			deadline := time.Now().Add(60 * time.Second)
			_ = local.SetDeadline(deadline)
			_ = peer.SetDeadline(deadline)
		}
		updateIdle()
		pump := func(dst, src net.Conn) {
			scratch := make([]byte, 65535)
			for {
				n, err := src.Read(scratch)
				if err != nil {
					break
				}
				updateIdle()
				// Exactly one application read/write per UDP datagram.
				written, err := dst.Write(scratch[:n])
				if err != nil || written != n {
					break
				}
			}
			closeBoth()
		}
		done := make(chan struct{})
		go func() { pump(peer, local); close(done) }()
		pump(local, peer)
		<-done
	}()
	return true
}
