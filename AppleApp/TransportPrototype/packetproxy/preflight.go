package packetproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"time"
)

// Check the actual selected leaf in both directions. The literal upstream address
// prevents local DNS resolution from silently taking a different path.
func (p *Plane) Preflight(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(p.life, timeout)
	defer cancel()
	query := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if _, err := rand.Read(query[:2]); err != nil {
		return err
	}
	valid := func(reply []byte) bool {
		return len(reply) >= len(query) && bytes.Equal(reply[:2], query[:2]) && reply[2]&128 != 0 &&
			reply[3]&15 == 0 && binary.BigEndian.Uint16(reply[4:6]) == 1 &&
			binary.BigEndian.Uint16(reply[6:8]) > 0 && bytes.Equal(reply[12:len(query)], query[12:])
	}
	deadline, _ := ctx.Deadline()
	peer, err := p.leaf.DialContext(ctx, "tcp", "1.1.1.1:443")
	if err != nil {
		return err
	}
	defer peer.Close()
	stop := context.AfterFunc(ctx, func() { _ = peer.Close() })
	defer stop()
	_ = peer.SetDeadline(deadline)
	encrypted := tls.Client(peer, &tls.Config{ServerName: "cloudflare-dns.com", MinVersion: tls.VersionTLS12})
	if err = encrypted.HandshakeContext(ctx); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, "POST", "https://cloudflare-dns.com/dns-query", bytes.NewReader(query))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	request.Close = true
	if err = request.Write(encrypted); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(encrypted), request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return err
	}
	if response.StatusCode != 200 || !valid(reply) {
		return errors.New("encrypted proxy TLS probe failed")
	}
	if !p.leaf.SupportsUDP() {
		return nil
	}
	datagram, err := p.leaf.DialContext(ctx, "udp", "1.1.1.1:53")
	if err != nil {
		return err
	}
	defer datagram.Close()
	stopUDP := context.AfterFunc(ctx, func() { _ = datagram.Close() })
	defer stopUDP()
	_ = datagram.SetDeadline(deadline)
	if _, err = rand.Read(query[:2]); err != nil {
		return err
	}
	if _, err = datagram.Write(query); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, err := datagram.Read(buf)
	if err != nil {
		return err
	}
	if !valid(buf[:n]) {
		return errors.New("encrypted proxy UDP probe failed")
	}
	return nil
}
