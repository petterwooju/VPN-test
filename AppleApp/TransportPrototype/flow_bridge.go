//go:build darwin

package main

/*
#include <stdint.h>
#include <string.h>
*/
import "C"
import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"coreavpn.local/packetbridge/proxyleaf"
	"golang.org/x/sys/unix"
)

type boundExit struct {
	Interface string          `json:"interface"`
	Index     int             `json:"index"`
	IPv4      string          `json:"ipv4"`
	Node      json.RawMessage `json:"node,omitempty"`
}

func (x boundExit) dial(ctx context.Context, network, host, port string) (net.Conn, func(), error) {
	binding := proxyleaf.Binding{Name: x.Interface, Index: x.Index, IPv4: x.IPv4}
	if !binding.Valid() {
		return nil, nil, errors.New("interface generation changed")
	}
	addr := net.JoinHostPort(host, port)
	if len(x.Node) == 0 {
		if _, err := netip.ParseAddr(host); err != nil {
			return nil, nil, errors.New("literal destination required")
		}
		dial, e := binding.Dialer()
		if e != nil {
			return nil, nil, e
		}
		c, e := dial.DialContext(ctx, network, addr)
		if e != nil {
			return nil, nil, e
		}
		if !binding.Valid() {
			c.Close()
			return nil, nil, errors.New("interface changed during connect")
		}
		return c, func() { c.Close() }, nil
	}
	var fields map[string]any
	if err := json.Unmarshal(x.Node, &fields); err != nil {
		return nil, nil, err
	}
	server, _ := fields["server"].(string)
	if addr, e := netip.ParseAddr(server); e != nil || !validEndpoint(addr) {
		return nil, nil, errors.New("numeric public peer required")
	}
	fields["interface-name"] = x.Interface
	fields["interface-index"] = x.Index
	fields["interface-ipv4"] = x.IPv4
	spec, err := json.Marshal(fields)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := proxyleaf.New(spec)
	clear(spec)
	if err != nil {
		return nil, nil, err
	}
	conn, err := leaf.DialContext(ctx, network, addr)
	if err != nil {
		leaf.Close()
		return nil, nil, err
	}
	closePair := func() { conn.Close(); leaf.Close() }
	if !binding.Valid() {
		closePair()
		return nil, nil, errors.New("interface changed during connect")
	}
	return conn, closePair, nil
}

func readExit(raw *C.char) (boundExit, bool) {
	var spec boundExit
	if raw == nil {
		return spec, false
	}
	n := C.strnlen(raw, 131073)
	if n == 0 || n > 131072 {
		return spec, false
	}
	b := C.GoBytes(unsafe.Pointer(raw), C.int(n))
	defer clear(b)
	err := json.Unmarshal(b, &spec)
	return spec, err == nil
}

//export CRouteProbe
func CRouteProbe(raw, rawURL *C.char) C.int {
	x, ok := readExit(raw)
	if !ok || rawURL == nil || C.strnlen(rawURL, 2049) > 2048 {
		return -1
	}
	u, err := url.Parse(C.GoString(rawURL))
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return -1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		conn, cleanup, err := x.dial(ctx, "tcp", host, port)
		if err != nil {
			return nil, err
		}
		return &cleanupConn{Conn: conn, cleanup: cleanup}, nil
	}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return -1
	}
	start := time.Now()
	resp, err := transport.RoundTrip(request)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return -1
	}
	return C.int(max(1, time.Since(start).Milliseconds()))
}

type cleanupConn struct {
	net.Conn
	cleanup func()
}

func (c *cleanupConn) Close() error { c.cleanup(); return nil }

//export CRouteOpen
func CRouteOpen(raw, target *C.char, port C.int, udp C.int) C.int {
	x, ok := readExit(raw)
	if !ok || target == nil || C.strnlen(target, 254) > 253 || port < 1 || port > 65535 || (udp != 0 && udp != 1) {
		return -1
	}
	host := C.GoString(target)
	if strings.ContainsAny(host, "\x00/[]") || host == "" {
		return -1
	}
	network := "tcp"
	if udp == 1 {
		network = "udp"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	remote, cleanup, err := x.dial(ctx, network, host, strconv.Itoa(int(port)))
	if err != nil {
		return -1
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		cleanup()
		return -1
	}
	unix.CloseOnExec(pair[0])
	unix.CloseOnExec(pair[1])
	localFile := os.NewFile(uintptr(pair[1]), "route")
	local, err := net.FileConn(localFile)
	localFile.Close()
	if err != nil {
		unix.Close(pair[0])
		cleanup()
		return -1
	}
	if err = unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_NOSIGPIPE, 1); err != nil {
		unix.Close(pair[0])
		local.Close()
		cleanup()
		return -1
	}
	go bridgeFlow(local, remote, network, cleanup)
	return C.int(pair[0])
}

func bridgeFlow(local, remote net.Conn, network string, cleanup func()) {
	defer local.Close()
	defer cleanup()
	done := make(chan struct{})
	go func() {
		defer close(done)
		var err error
		if network == "udp" {
			err = unframeDatagrams(remote, local)
		} else {
			_, err = io.Copy(remote, local)
		}
		if err == nil && network == "tcp" {
			if closer, ok := remote.(interface{ CloseWrite() error }); ok {
				closer.CloseWrite()
			}
			// A FIN still permits a response. Bound the drain for peers without a half-close API.
			remote.SetReadDeadline(time.Now().Add(2 * time.Minute))
		} else {
			remote.Close()
		}
	}()
	if network == "udp" {
		frameDatagrams(local, remote)
	} else {
		io.Copy(local, remote)
	}
	if c, ok := local.(interface{ CloseWrite() error }); ok {
		c.CloseWrite()
	}
	local.SetReadDeadline(time.Now().Add(2 * time.Minute))
	// Wait for the upload, permitting TCP peers which half-close first to keep reading.
	<-done
}

func frameDatagrams(dst io.Writer, src net.Conn) error {
	slab := make([]byte, 65537)
	for {
		n, err := src.Read(slab[2:])
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(slab, uint16(n))
		if _, err = dst.Write(slab[:2+n]); err != nil {
			return err
		}
	}
}
func unframeDatagrams(dst net.Conn, src io.Reader) error {
	slab := make([]byte, 65535)
	var length [2]byte
	for {
		if _, err := io.ReadFull(src, length[:]); err != nil {
			return err
		}
		packet := slab[:int(binary.BigEndian.Uint16(length[:]))]
		if _, err := io.ReadFull(src, packet); err != nil {
			return err
		}
		if n, err := dst.Write(packet); err != nil {
			return err
		} else if n != len(packet) {
			return io.ErrShortWrite
		}
	}
}
