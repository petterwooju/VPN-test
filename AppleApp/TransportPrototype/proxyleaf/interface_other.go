//go:build !darwin

package proxyleaf

import (
	"errors"
	"net"
)

func setInterface(_ *net.Dialer, name string) error {
	if name != "" {
		return errors.New("interface scoping requires an Apple platform")
	}
	return nil
}

func bindGeneration(_ *net.Dialer, _ Binding) error {
	return errors.New("interface scoping requires an Apple platform")
}
