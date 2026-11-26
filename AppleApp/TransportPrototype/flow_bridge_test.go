//go:build darwin

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func loopbackExit(t *testing.T) boundExit {
	t.Helper()
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	return boundExit{Interface: "lo0", Index: iface.Index, IPv4: "127.0.0.1"}
}

func TestBoundFlowWrongGenerationAndDNS(t *testing.T) {
	x := loopbackExit(t)
	x.Index++
	for _, network := range []string{"tcp", "udp"} {
		if _, _, err := x.dial(context.Background(), network, "127.0.0.1", "1"); err == nil {
			t.Fatal("accepted changed interface generation")
		}
	}
	x = loopbackExit(t)
	if _, _, err := x.dial(context.Background(), "udp", "example.invalid", "1"); err == nil {
		t.Fatal("allowed unscoped DNS")
	}
}

func TestBoundFlowDuplexTCP(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, e := listener.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		data, _ := io.ReadAll(c)
		c.Write(append([]byte("received:"), data...))
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	conn, cleanup, err := loopbackExit(t).dial(context.Background(), "tcp", host, port)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err = conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	conn.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "received:hello" {
		t.Fatalf("response %q, %v", got, err)
	}
}

func TestBoundFlowFramedUDP(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		var p [64]byte
		for {
			n, peer, e := listener.ReadFrom(p[:])
			if e != nil {
				return
			}
			listener.WriteTo(p[:n], peer)
		}
	}()
	host, port, _ := net.SplitHostPort(listener.LocalAddr().String())
	remote, cleanup, err := loopbackExit(t).dial(context.Background(), "udp", host, port)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	go bridgeFlow(a, remote, "udp", cleanup)
	defer b.Close()
	b.SetDeadline(time.Now().Add(4 * time.Second))
	for _, payload := range [][]byte{{}, []byte("packet 1"), {0, 1, 2, 3}} {
		frame := binary.BigEndian.AppendUint16(nil, uint16(len(payload)))
		frame = append(frame, payload...)
		if _, e := b.Write(frame); e != nil {
			t.Fatal(e)
		}
		reply := make([]byte, len(frame))
		if _, e := io.ReadFull(b, reply); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(frame, reply) {
			t.Fatal("datagram boundary or bytes changed")
		}
	}
}
