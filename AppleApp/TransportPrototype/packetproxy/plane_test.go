package packetproxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
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
)

type echoLeaf struct{ selected chan string }

func (e echoLeaf) SupportsUDP() bool { return true }
func (e echoLeaf) Close()            {}
func (e echoLeaf) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	e.selected <- network + " " + address
	user, echo := net.Pipe()
	go func() {
		defer echo.Close()
		scratch := make([]byte, 65535)
		for {
			n, err := echo.Read(scratch)
			if err != nil {
				return
			}
			if _, err = echo.Write(scratch[:n]); err != nil {
				return
			}
		}
	}()
	return user, nil
}

func TestRawTCPAndDatagramRoundTrip(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) { exerciseRoundTrip(t, ipv4.ProtocolNumber, "10.2.0.8", "203.0.113.41") })
	t.Run("IPv6", func(t *testing.T) { exerciseRoundTrip(t, ipv6.ProtocolNumber, "fd00::8", "2001:db8::41") })
}

func exerciseRoundTrip(t *testing.T, family tcpip.NetworkProtocolNumber, source, target string) {
	leaf := echoLeaf{selected: make(chan string, 4)}
	exerciseSelectedLeaf(t, family, source, target, leaf, leaf.selected)
}

func exerciseSelectedLeaf(t *testing.T, family tcpip.NetworkProtocolNumber, source, target string, leaf Dialer, selected <-chan string) {
	// Two independent IP stacks exchange raw packets entirely in memory.
	// The only egress available to the forwarding stack is the selected fake leaf.
	plane, err := New(leaf)
	if err != nil {
		t.Fatal(err)
	}
	client := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	pipe := channel.New(64, 1280, "")
	if err := client.CreateNIC(1, pipe); err != nil {
		t.Fatal(err)
	}
	own := tcpip.AddrFromSlice(netip.MustParseAddr(source).AsSlice())
	if err := client.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: family,
		AddressWithPrefix: own.WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	client.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() { cancel(); plane.Close(); client.Close(); pipe.Close(); client.Wait() }()
	go func() {
		for {
			pkt := pipe.ReadContext(ctx)
			if pkt == nil {
				return
			}
			raw := pkt.ToView()
			_ = plane.Write(raw.AsSlice())
			raw.Release()
			pkt.DecRef()
		}
	}()
	go func() {
		scratch := make([]byte, 65535)
		for ctx.Err() == nil {
			n, err := plane.Read(scratch, 50*time.Millisecond)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), scratch[:n]...))})
			pipe.InjectInbound(family, pkt)
			pkt.DecRef()
		}
	}()
	remote := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(netip.MustParseAddr(target).AsSlice()), Port: 8443}
	for _, network := range []string{"tcp", "udp"} {
		var conn net.Conn
		if network == "tcp" {
			conn, err = gonet.DialContextTCP(ctx, client, remote, family)
		} else {
			conn, err = gonet.DialUDP(client, nil, &remote, family)
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		for _, body := range []string{"first", "a different length for second datagram"} {
			if _, err = conn.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(body))
			if _, err = io.ReadFull(conn, reply); err != nil || !bytes.Equal([]byte(body), reply) {
				t.Fatalf("%s reply %q: %v", network, reply, err)
			}
		}
		_ = conn.Close()
		if got := <-selected; got != network+" "+net.JoinHostPort(target, "8443") {
			t.Fatal(got)
		}
	}
}

func TestICMPIsNotProxied(t *testing.T) {
	leaf := echoLeaf{selected: make(chan string, 1)}
	p, err := New(leaf)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[3] = 28
	packet[9] = 1
	if err = p.Write(packet); err != ErrUnsupported {
		t.Fatal(err)
	}
	select {
	case got := <-leaf.selected:
		t.Fatalf("ICMP caused outbound dial: %s", got)
	default:
	}
}
