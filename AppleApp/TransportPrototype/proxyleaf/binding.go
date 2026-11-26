package proxyleaf

import (
	"errors"
	"net"
	"net/netip"
)

// Binding identifies one generation of an interface. Reuse of its BSD name
// after a network change must never silently send a flow along another route.
type Binding struct {
	Name  string
	Index int
	IPv4  string
}

func (b Binding) Valid() bool {
	iface, err := net.InterfaceByName(b.Name)
	expected, parseErr := netip.ParseAddr(b.IPv4)
	if err != nil || parseErr != nil || !expected.Is4() || iface.Index != b.Index || iface.Flags&net.FlagUp == 0 {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if prefix, err := netip.ParsePrefix(addr.String()); err == nil && prefix.Addr().Unmap() == expected {
			return true
		}
	}
	return false
}

func (b Binding) Dialer() (*net.Dialer, error) {
	if !b.Valid() {
		return nil, errors.New("interface changed")
	}
	var d net.Dialer
	if err := bindGeneration(&d, b); err != nil {
		return nil, err
	}
	return &d, nil
}
