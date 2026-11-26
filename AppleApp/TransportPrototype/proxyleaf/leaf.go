// Package proxyleaf dials authenticated TCP and datagram connections through a selected remote proxy.
package proxyleaf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	obfs "github.com/Dreamacro/clash/transport/simple-obfs"
	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

var invalid = errors.New("invalid or unsupported saved proxy configuration")

type options struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Server     string `json:"server"`
	Port       uint16 `json:"port"`
	Password   string `json:"password"`
	UDP        bool   `json:"udp"`
	UOT        bool   `json:"udp-over-tcp"`
	UOTVersion uint8  `json:"udp-over-tcp-version"`
	Cipher     string `json:"cipher"`
	Plugin     string `json:"plugin"`
	PluginOpts *struct {
		Host string `json:"host"`
		Mode string `json:"mode"`
	} `json:"plugin-opts"`
	SNI            string   `json:"sni"`
	Fingerprint    string   `json:"fingerprint"`
	SkipCert       bool     `json:"skip-cert-verify"`
	ALPN           []string `json:"alpn"`
	IdleCheck      int      `json:"idle-session-check-interval"`
	IdleTimeout    int      `json:"idle-session-timeout"`
	MinIdle        int      `json:"min-idle-session"`
	InterfaceIndex int      `json:"interface-index"`
	InterfaceIPv4  string   `json:"interface-ipv4"`
	Interface      string   `json:"interface-name"` // trusted provider/diagnostic can scope the transport
}

type Leaf struct {
	opts options
	ss   *shadowaead.Method
	any  *anytls.Client
	dial net.Dialer
}

func New(spec []byte) (*Leaf, error) {
	if len(spec) == 0 || len(spec) > 65536 {
		return nil, invalid
	}
	var o options
	d := json.NewDecoder(bytes.NewReader(spec))
	d.DisallowUnknownFields()
	if d.Decode(&o) != nil || d.Decode(new(any)) != io.EOF {
		return nil, invalid
	}
	if o.Server == "" || o.Port == 0 || o.Password == "" || o.SkipCert || o.IdleCheck < 0 ||
		o.IdleTimeout < 0 || o.MinIdle < 0 || o.MinIdle > 64 || o.IdleCheck > 86400 || o.IdleTimeout > 86400 {
		return nil, invalid
	}
	if o.UOTVersion == 0 {
		o.UOTVersion = 2
		if o.Type == "ss" {
			o.UOTVersion = 1 // mihomo defaults Shadowsocks UoT to its legacy framing
		}
	}
	if o.UOTVersion != 1 && o.UOTVersion != 2 {
		return nil, invalid
	}
	l := &Leaf{opts: o, dial: net.Dialer{Timeout: 12 * time.Second}}
	if o.InterfaceIndex != 0 || o.InterfaceIPv4 != "" {
		b := Binding{Name: o.Interface, Index: o.InterfaceIndex, IPv4: o.InterfaceIPv4}
		dial, e := b.Dialer()
		if e != nil {
			return nil, e
		}
		l.dial = *dial
		l.dial.Timeout = 12 * time.Second
	} else if err := setInterface(&l.dial, o.Interface); err != nil {
		return nil, err
	}
	switch o.Type {
	case "ss":
		if o.Cipher != "chacha20-ietf-poly1305" && o.Cipher != "aes-128-gcm" && o.Cipher != "aes-256-gcm" {
			return nil, invalid
		}
		if o.Plugin != "" || o.PluginOpts != nil {
			if o.Plugin != "obfs" || o.PluginOpts == nil || o.PluginOpts.Host == "" ||
				(o.PluginOpts.Mode != "tls" && o.PluginOpts.Mode != "http") {
				return nil, invalid
			}
		}
		if o.UDP && !o.UOT {
			return nil, invalid
		}
		method, err := shadowaead.New(o.Cipher, nil, o.Password)
		if err != nil {
			return nil, invalid
		}
		l.ss = method
	case "anytls":
		if o.SNI == "" {
			return nil, invalid
		}
		tlsOpts := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: o.SNI, NextProtos: o.ALPN}
		if o.Fingerprint != "" {
			pin, err := hex.DecodeString(strings.ReplaceAll(o.Fingerprint, ":", ""))
			if err != nil || len(pin) != sha256.Size {
				return nil, invalid
			}
			// A user-supplied leaf pin is an explicit trust anchor. Require the pinned
			// cert's name and validity period too. An unverified fallback is never used.
			tlsOpts.InsecureSkipVerify = true
			tlsOpts.VerifyConnection = func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 {
					return errors.New("proxy peer certificate missing")
				}
				cert := state.PeerCertificates[0]
				digest := sha256.Sum256(cert.Raw)
				now := time.Now()
				if subtle.ConstantTimeCompare(pin, digest[:]) != 1 || now.Before(cert.NotBefore) || now.After(cert.NotAfter) ||
					cert.VerifyHostname(o.SNI) != nil {
					return errors.New("proxy peer certificate verification failed")
				}
				return nil
			}
		}
		dial := &tls.Dialer{NetDialer: &l.dial, Config: tlsOpts}
		anyClient, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
			Password: o.Password, IdleSessionCheckInterval: time.Duration(o.IdleCheck) * time.Second,
			IdleSessionTimeout: time.Duration(o.IdleTimeout) * time.Second, MinIdleSession: o.MinIdle,
			Logger: logger.NOP(), DialOut: func(ctx context.Context) (net.Conn, error) {
				return dial.DialContext(ctx, "tcp", l.serverAddress())
			}})
		if err != nil {
			return nil, invalid
		}
		l.any = anyClient
	default:
		return nil, invalid
	}
	return l, nil
}

func (l *Leaf) serverAddress() string {
	return net.JoinHostPort(l.opts.Server, strconv.Itoa(int(l.opts.Port)))
}
func (l *Leaf) SupportsUDP() bool { return l.opts.UDP && (l.any != nil || l.opts.UOT) }
func (l *Leaf) Close() {
	if l.any != nil {
		_ = l.any.Close()
	}
}

func (l *Leaf) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, invalid
	}
	host, port, err := net.SplitHostPort(address)
	n, parseErr := strconv.ParseUint(port, 10, 16)
	if err != nil || parseErr != nil || host == "" || n == 0 {
		return nil, invalid
	}
	destination := M.ParseSocksaddrHostPort(host, uint16(n))
	remote := destination
	if network == "udp" {
		if !l.SupportsUDP() {
			return nil, errors.New("selected group member has UDP disabled")
		}
		remote = uot.RequestDestination(l.opts.UOTVersion)
	}
	var stream net.Conn
	if l.any != nil {
		stream, err = l.any.CreateProxy(ctx, remote)
	} else {
		raw, dialErr := l.dial.DialContext(ctx, "tcp", l.serverAddress())
		if dialErr != nil {
			return nil, dialErr
		}
		if l.opts.PluginOpts != nil {
			opt := l.opts.PluginOpts
			if opt.Mode == "tls" {
				raw = obfs.NewTLSObfs(raw, opt.Host)
			} else {
				raw = obfs.NewHTTPObfs(raw, opt.Host, strconv.Itoa(int(l.opts.Port)))
			}
		}
		// SS sends its authenticated first frame during DialConn.
		deadline := time.Now().Add(12 * time.Second)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		_ = raw.SetDeadline(deadline)
		stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
		stream, err = l.ss.DialConn(raw, remote)
		stop()
		if err != nil {
			_ = raw.Close()
		}
		if err == nil {
			_ = stream.SetDeadline(time.Time{})
		}
	}
	if err != nil {
		return nil, err
	}
	if network == "tcp" {
		return stream, nil
	}
	legacy := l.opts.UOTVersion == 1
	if !legacy {
		stream = uot.NewLazyClientConn(stream, uot.Request{IsConnect: true, Destination: destination})
	}
	return &connectedDatagrams{Conn: stream, peer: destination, legacy: legacy}, nil
}

// The sing UoT packet API can report framed bytes rather than application bytes.
// Expose connected UDP semantics, preserving datagrams and validating v1 sender addresses.
type connectedDatagrams struct {
	net.Conn
	peer     M.Socksaddr
	legacy   bool
	rmu, wmu sync.Mutex
}

func (c *connectedDatagrams) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if len(p) > 65535 {
		return 0, errors.New("UDP datagram too large")
	}
	var frame bytes.Buffer
	if c.legacy {
		if err := uot.AddrParser.WriteAddrPort(&frame, c.peer); err != nil {
			return 0, err
		}
	}
	frame.WriteByte(byte(len(p) >> 8))
	frame.WriteByte(byte(len(p)))
	frame.Write(p)
	n, err := c.Conn.Write(frame.Bytes())
	if err != nil {
		return 0, err
	}
	if n != frame.Len() {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (c *connectedDatagrams) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		matched := true
		if c.legacy {
			source, err := uot.AddrParser.ReadAddrPort(c.Conn)
			if err != nil {
				return 0, err
			}
			matched = source == c.peer
		}
		var length uint16
		if err := binary.Read(c.Conn, binary.BigEndian, &length); err != nil {
			return 0, err
		}
		if !matched {
			if _, err := io.CopyN(io.Discard, c.Conn, int64(length)); err != nil {
				return 0, err
			}
			continue
		}
		size := min(len(p), int(length))
		n, err := io.ReadFull(c.Conn, p[:size])
		if err != nil {
			return n, err
		}
		if size < int(length) {
			_, err = io.CopyN(io.Discard, c.Conn, int64(int(length)-size))
		}
		return n, err
	}
}
