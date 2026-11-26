package proxyleaf

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

type echoPeer struct{}

func (echoPeer) NewConnectionEx(ctx context.Context, stream net.Conn, from, dest M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer stream.Close()
		if dest.Fqdn == uot.MagicAddress {
			request, err := uot.ReadRequest(stream)
			if err != nil {
				return
			}
			datagrams := uot.NewConn(stream, *request)
			b := make([]byte, 1400)
			for {
				n, err := datagrams.Read(b)
				if err != nil {
					return
				}
				if _, err = datagrams.Write(b[:n]); err != nil {
					return
				}
			}
		}
		_, _ = io.Copy(stream, stream)
	}()
}

func TestAnyTLSPinnedTCPAndUDP(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"fixture.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	handler, err := anytls.NewService(anytls.ServiceConfig{PaddingScheme: padding.DefaultPaddingScheme, Users: []anytls.User{{Name: "fixture", Password: "test-only"}},
		Logger: logger.NOP(), Handler: echoPeer{}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = handler.NewConnection(context.Background(), c, M.Socksaddr{}, nil) }()
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	hash := sha256.Sum256(der)
	conf := map[string]any{"type": "anytls", "server": "127.0.0.1", "port": p, "sni": "fixture.test", "fingerprint": hex.EncodeToString(hash[:]), "password": "test-only", "udp": true}
	spec, _ := json.Marshal(conf)
	leaf, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer leaf.Close()
	for _, kind := range []string{"tcp", "udp"} {
		c, err := leaf.DialContext(context.Background(), kind, "192.0.2.9:99")
		if err != nil {
			t.Fatal(err)
		}
		if err = c.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
			t.Fatal(err)
		}
		for _, payload := range []string{"first", "a second datagram"} {
			_, err = c.Write([]byte(payload))
			if err != nil {
				t.Fatal(err)
			}
			b := make([]byte, len(payload))
			if _, err = io.ReadFull(c, b); err != nil || string(b) != payload {
				t.Fatalf("%s echo failed: %v", kind, err)
			}
		}
		c.Close()
	}
	hash[0] ^= 255
	conf["fingerprint"] = hex.EncodeToString(hash[:])
	spec, _ = json.Marshal(conf)
	bad, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if c, err := bad.DialContext(context.Background(), "tcp", "192.0.2.4:443"); err == nil {
		c.Close()
		t.Fatal("trusted a mismatched pin")
	}
	conf["skip-cert-verify"] = true
	spec, _ = json.Marshal(conf)
	if _, err = New(spec); err == nil {
		t.Fatal("accepted insecure profile")
	}
}
