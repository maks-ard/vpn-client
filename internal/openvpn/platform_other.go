//go:build !windows

package openvpn

import (
	"os/exec"
)

func platformArgs() []string { return nil }

// Find ищет openvpn в PATH: вне Windows это нужно только для разработки и тестов.
func Find() (string, error) {
	path, err := exec.LookPath("openvpn")
	if err != nil {
		return "", ErrNotFound
	}
	return path, nil
}
