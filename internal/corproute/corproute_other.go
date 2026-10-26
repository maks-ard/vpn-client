//go:build !windows

package corproute

import (
	"errors"
	"net/netip"
)

// Ensure на других системах не поддерживается: приложение работает только
// на Windows, а тесты подменяют вызов.
func Ensure(name string, hosts []netip.Addr) (int, error) {
	return 0, errors.ErrUnsupported
}
