package proxyleaf

import (
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"strings"
	"syscall"
)

func setInterface(dial *net.Dialer, name string) error {
	if name == "" {
		return nil
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	return bindSocket(dial, iface.Index, nil)
}

func bindGeneration(dial *net.Dialer, binding Binding) error {
	return bindSocket(dial, binding.Index, binding.Valid)
}

func bindSocket(dial *net.Dialer, index int, current func() bool) error {
	dial.Control = func(network, address string, raw syscall.RawConn) error {
		if current != nil && !current() {
			return errors.New("network interface changed before connect")
		}
		var result error
		err := raw.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				result = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
			} else {
				result = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
			}
		})
		if err != nil {
			return err
		}
		return result
	}
	return nil
}
