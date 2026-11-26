//go:build loopback_fixture

package packetproxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"testing"

	"coreavpn.local/packetbridge/proxyleaf"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// Only this in-process echo responder can receive the ephemeral fixture credentials;
// the TCP socket binds exclusively to 127.0.0.1. No external endpoint is involved.
type encryptedEcho struct{ selected chan string }

type checkedLeaf struct {
	Dialer
	t *testing.T
}

type checkedDatagram struct {
	net.Conn
	t *testing.T
}

func (l checkedLeaf) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := l.Dialer.DialContext(ctx, network, address)
	if err != nil || network != "udp" {
		return c, err
	}
	return checkedDatagram{Conn: c, t: l.t}, nil
}

func (c checkedDatagram) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err == nil && n != len(p) {
		c.t.Errorf("connected UDP wrote %d payload bytes, expected %d", n, len(p))
	}
	return n, err
}

func (e encryptedEcho) NewError(context.Context, error) {}
func (e encryptedEcho) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return errors.New("unexpected raw UDP")
}
func (e encryptedEcho) NewConnection(ctx context.Context, c net.Conn, m M.Metadata) error {
	defer c.Close()
	if m.Destination.Fqdn == uot.LegacyMagicAddress || m.Destination.Fqdn == uot.MagicAddress {
		var request uot.Request
		if m.Destination.Fqdn == uot.MagicAddress {
			req, err := uot.ReadRequest(c)
			if err != nil {
				return err
			}
			request = *req
		}
		datagrams := uot.NewConn(c, request)
		scratch := make([]byte, 65535)
		first := true
		for {
			n, address, err := datagrams.ReadFrom(scratch)
			if err != nil {
				return err
			}
			if first {
				e.selected <- "udp " + address.String()
				first = false
			}
			if _, err = datagrams.WriteTo(scratch[:n], address); err != nil {
				return err
			}
		}
	}
	e.selected <- "tcp " + m.Destination.String()
	scratch := make([]byte, 65535)
	for {
		n, err := c.Read(scratch)
		if err != nil {
			return err
		}
		if _, err = c.Write(scratch[:n]); err != nil {
			return err
		}
	}
}

func TestEncryptedShadowsocksPacketFlow(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(nonce[:])
	handler := encryptedEcho{selected: make(chan string, 4)}
	service, err := shadowaead.NewService("aes-128-gcm", nil, password, 30, handler)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = service.NewConnection(context.Background(), c, M.Metadata{Source: M.SocksaddrFromNet(c.RemoteAddr())})
			}(c)
		}
	}()
	spec, err := json.Marshal(map[string]any{"type": "ss", "server": "127.0.0.1", "port": listener.Addr().(*net.TCPAddr).Port,
		"password": password, "cipher": "aes-128-gcm", "udp": true, "udp-over-tcp": true, "udp-over-tcp-version": 1})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := proxyleaf.New(spec)
	if err != nil {
		t.Fatal(err)
	}
	exerciseSelectedLeaf(t, ipv4.ProtocolNumber, "10.2.0.8", "203.0.113.41", checkedLeaf{leaf, t}, handler.selected)
}
