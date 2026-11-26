package main

import (
	"net/netip"
	"slices"
	"testing"
)

func TestPacketAndHostLimits(t *testing.T) {
	if allowedHost("puma.coreavpn.net.foreign.example") || allowedHost("puma.coreavpn.kr") || !allowedHost("puma.coreavpn.net") {
		t.Fatal("IKE identity allowlist mismatch")
	}
	for _, ip := range []string{"100.64.5.1", "198.18.0.2", "203.0.113.1", "10.200.0.7", "::ffff:192.168.0.5"} {
		if validEndpoint(netip.MustParseAddr(ip)) {
			t.Fatalf("accepted non-public endpoint %s", ip)
		}
	}
	if !validEndpoint(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public server address was rejected")
	}
	small := make([]byte, 19)
	small[0] = 0x45
	v6 := make([]byte, 40)
	v6[0] = 0x60
	if validPacket(small) || !validPacket(v6) || validPacket(slices.Concat([]byte{0x50}, v6)) {
		t.Fatal("packet family or size check failed")
	}
}
