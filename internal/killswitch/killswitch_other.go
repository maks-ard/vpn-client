//go:build !windows

package killswitch

import "errors"

// Firewall на других системах не реализован: приложение работает только в
// Windows, а здесь пакет нужен для сборки и тестов.
type Firewall struct{}

func Enable(Rules) (*Firewall, error) {
	return nil, errors.New("kill switch работает только в Windows")
}

func (f *Firewall) Update(Rules) error { return nil }

func (f *Firewall) Close() error { return nil }
