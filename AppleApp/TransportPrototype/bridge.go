// Package main exposes a small C ABI for NetworkExtension's packetFlow.
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	ipsec "github.com/n0madic/go-ipsec"
)

const maximumPacket = 65535

type session struct {
	mu         sync.Mutex
	lifetime   context.Context
	cancel     context.CancelFunc
	connecting chan struct{}
	client     *ipsec.Client
	pipe       net.Conn
	packets    chan []byte
}

var sessions sync.Map
var serial atomic.Uint64

func find(handle C.uint64_t) *session {
	value, ok := sessions.Load(uint64(handle))
	if !ok {
		return nil
	}
	return value.(*session)
}

//export CVPNCreate
func CVPNCreate() C.uint64_t {
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{lifetime: ctx, cancel: cancel, packets: make(chan []byte, 64)}
	id := serial.Add(1)
	sessions.Store(id, s)
	return C.uint64_t(id)
}

func allowedHost(host string) bool {
	label, suffix, ok := strings.Cut(host, ".")
	if !ok {
		return false
	}
	switch suffix {
	case "coreavpn.net":
		return slices.Contains(strings.Fields("lynx puma saturn ibex lion titan hornet venus wolf oryx gannet leo falcon hawk cougar moon eagle"), label)
	case "coreavpn.com":
		return slices.Contains(strings.Fields("lynx puma gannet moon"), label)
	case "coreavpn.kr":
		return label == "lynx" || label == "venus"
	}
	return false
}

func validEndpoint(ip netip.Addr) bool {
	// The CoreaVPN DNS catalog currently supplies public IPv4 endpoints exclusively.
	// Also refuse proxy fake-IP space and ranges that IsGlobalUnicast includes.
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	a := ip.As4()
	if a[0] == 0 || a[0] >= 224 || (a[0] == 100 && a[1]&0xc0 == 64) || (a[0] == 198 && a[1]&0xfe == 18) {
		return false
	}
	prefix := [3]byte{a[0], a[1], a[2]}
	switch prefix {
	case [3]byte{192, 0, 0}, [3]byte{192, 0, 2}, [3]byte{192, 88, 99}, [3]byte{198, 51, 100}, [3]byte{203, 0, 113}:
		return false
	}
	return true
}

func validPacket(packet []byte) bool {
	if len(packet) == 0 || len(packet) > maximumPacket {
		return false
	}
	switch packet[0] >> 4 {
	case 4:
		return len(packet) >= 20
	case 6:
		return len(packet) >= 40
	default:
		return false
	}
}

// A session uses exactly one consumer of the raw tunnel; never initialize its optional TCP/IP netstack.
func (s *session) attach(client *ipsec.Client) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lifetime.Err() != nil {
		return false
	}
	client.Tunnel().SetInbound(func(packet []byte) {
		if !validPacket(packet) || s.lifetime.Err() != nil {
			return
		}
		// The library reuses this slice after the callback returns.
		select {
		case s.packets <- slices.Clone(packet):
		default: // Bounded receive queue: a slow OS reader cannot retain unbounded decrypted traffic.
		}
	})
	s.client = client
	s.pipe = client.Tunnel().TunnelConn()
	// Inbound is delivered exclusively via SetInbound. The raw connection's Read
	// wakes on SA close, which propagates remote death to a waiting CVPNRead.
	go func(pipe net.Conn) {
		var unused [1]byte
		_, _ = pipe.Read(unused[:])
		s.cancel()
	}(s.pipe)
	return true
}

//export CVPNConnect
func CVPNConnect(handle C.uint64_t, address, remoteHost, username, password *C.char, timeout C.int) C.int {
	s := find(handle)
	if s == nil {
		return -1
	}
	if address == nil || remoteHost == nil || username == nil || password == nil || timeout <= 0 || timeout > 120000 {
		return -2
	}
	ip, err := netip.ParseAddr(C.GoString(address))
	host := C.GoString(remoteHost)
	user, pass := C.GoString(username), C.GoString(password)
	if err != nil || !validEndpoint(ip) || !allowedHost(host) || user == "" || pass == "" {
		return -2
	}
	s.mu.Lock()
	if s.connecting != nil || s.lifetime.Err() != nil {
		s.mu.Unlock()
		return -1
	}
	finished := make(chan struct{})
	s.connecting = finished
	s.mu.Unlock()
	defer close(finished)
	ctx, cancel := context.WithTimeout(s.lifetime, time.Duration(timeout)*time.Millisecond)
	defer cancel()
	reconnect := false // A new virtual address needs a fresh OS route configuration.
	client, err := ipsec.Dial(ctx, ipsec.Config{
		Server: net.JoinHostPort(ip.String(), "500"), RemoteID: ipsec.FQDN(host),
		EAP: ipsec.EAPMSCHAPv2{Username: user, Password: pass}, AutoReconnect: &reconnect,
	})
	if err != nil {
		// No raw errors cross the ABI. They may contain peer-supplied identities.
		if ctx.Err() != nil {
			return -3
		}
		return -4
	}
	if !s.attach(client) {
		_ = client.Close()
		return -1
	}
	return 0
}

func putAddress(out *C.char, cap C.int, address netip.Addr) bool {
	value := ""
	if address.IsValid() {
		value = address.String()
	}
	if out == nil || int(cap) <= len(value) {
		return false
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), len(value)+1)
	copy(dst, value)
	dst[len(value)] = 0
	return true
}

//export CVPNAddresses
func CVPNAddresses(handle C.uint64_t, ipv4 *C.char, cap4 C.int, ipv6 *C.char, cap6 C.int) C.int {
	s := find(handle)
	if s == nil {
		return -1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil || s.lifetime.Err() != nil {
		return -1
	}
	if !putAddress(ipv4, cap4, s.client.LocalIP()) || !putAddress(ipv6, cap6, s.client.LocalIP6().Addr()) {
		return -2
	}
	return 0
}

//export CVPNRead
func CVPNRead(handle C.uint64_t, buffer unsafe.Pointer, cap C.int, timeout C.int) C.int {
	s := find(handle)
	if s == nil || s.lifetime.Err() != nil {
		return -1
	}
	if buffer == nil || cap <= 0 || timeout <= 0 || timeout > 60000 {
		return -2
	}
	select {
	case <-s.lifetime.Done():
		return -1
	case <-time.After(time.Duration(timeout) * time.Millisecond):
		return 0
	case packet := <-s.packets:
		if s.lifetime.Err() != nil {
			return -1
		}
		if len(packet) > int(cap) {
			return -2
		}
		copy(unsafe.Slice((*byte)(buffer), len(packet)), packet)
		return C.int(len(packet))
	}
}

//export CVPNWrite
func CVPNWrite(handle C.uint64_t, buffer unsafe.Pointer, size C.int) C.int {
	s := find(handle)
	if s == nil || s.lifetime.Err() != nil {
		return -1
	}
	if buffer == nil || size <= 0 || size > maximumPacket {
		return -2
	}
	ip := unsafe.Slice((*byte)(buffer), int(size))
	if !validPacket(ip) {
		return -2
	}
	s.mu.Lock()
	pipe := s.pipe
	s.mu.Unlock()
	if pipe == nil {
		return -1
	}
	n, err := pipe.Write(ip)
	if err != nil || n != int(size) {
		return -1
	}
	return C.int(n)
}

//export CVPNClose
func CVPNClose(handle C.uint64_t) {
	value, ok := sessions.LoadAndDelete(uint64(handle))
	if !ok {
		return
	}
	s := value.(*session)
	s.cancel()
	s.mu.Lock()
	finished := s.connecting
	s.mu.Unlock()
	if finished != nil {
		<-finished
	}
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
}

func main() {}
