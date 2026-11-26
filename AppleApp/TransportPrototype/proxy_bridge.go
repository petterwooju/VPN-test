package main

/*
#include <stdint.h>
#include <string.h>
*/
import "C"

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"coreavpn.local/packetbridge/packetproxy"
	"coreavpn.local/packetbridge/proxyleaf"
)

type proxySession struct {
	plane *packetproxy.Plane
	ready atomic.Bool
}

var proxySessions sync.Map

func proxyHandle(h C.uint64_t) *proxySession {
	entry, ok := proxySessions.Load(uint64(h))
	if !ok {
		return nil
	}
	return entry.(*proxySession)
}

//export CProxyCreate
func CProxyCreate(configuration *C.char) C.uint64_t {
	if configuration == nil {
		return 0
	}
	const maximumConfig = 65536
	n := C.strnlen(configuration, maximumConfig+1)
	if n == 0 || n > maximumConfig {
		return 0
	}
	encoded := C.GoBytes(unsafe.Pointer(configuration), C.int(n))
	leaf, e := proxyleaf.New(encoded)
	clear(encoded)
	if e != nil {
		return 0
	}
	plane, e := packetproxy.New(leaf)
	if e != nil {
		leaf.Close()
		return 0
	}
	id := serial.Add(1)
	proxySessions.Store(id, &proxySession{plane: plane})
	return C.uint64_t(id)
}

//export CProxyPreflight
func CProxyPreflight(handle C.uint64_t, timeout C.int) C.int {
	s := proxyHandle(handle)
	if s == nil {
		return -1
	}
	if timeout <= 0 || timeout > 120000 {
		return -2
	}
	s.ready.Store(false)
	if err := s.plane.Preflight(time.Duration(timeout) * time.Millisecond); err != nil {
		return -4
	}
	if s.plane.Lifetime().Err() != nil {
		return -1
	}
	s.ready.Store(true)
	return 0
}

//export CProxyRead
func CProxyRead(handle C.uint64_t, buffer unsafe.Pointer, cap C.int, timeout C.int) C.int {
	s := proxyHandle(handle)
	if s == nil {
		return -1
	}
	if !s.ready.Load() {
		return -4
	}
	if buffer == nil || cap <= 0 || timeout <= 0 || timeout > 60000 {
		return -2
	}
	// IPv4/IPv6 datagrams fit the advertised packetFlow read window.
	size := min(int(cap), maximumPacket)
	n, err := s.plane.Read(unsafe.Slice((*byte)(buffer), size), time.Duration(timeout)*time.Millisecond)
	if errors.Is(err, packetproxy.ErrBuffer) {
		return -2
	}
	if err != nil {
		return -1
	}
	return C.int(n)
}

//export CProxyWrite
func CProxyWrite(handle C.uint64_t, buffer unsafe.Pointer, size C.int) C.int {
	s := proxyHandle(handle)
	if s == nil {
		return -1
	}
	if !s.ready.Load() {
		return -4
	}
	if buffer == nil || size <= 0 || size > maximumPacket {
		return -2
	}
	err := s.plane.Write(unsafe.Slice((*byte)(buffer), int(size)))
	if errors.Is(err, packetproxy.ErrUnsupported) {
		return -2
	}
	if err != nil {
		return -1
	}
	return size
}

//export CProxyClose
func CProxyClose(handle C.uint64_t) {
	value, ok := proxySessions.LoadAndDelete(uint64(handle))
	if ok {
		value.(*proxySession).plane.Close()
	}
}
