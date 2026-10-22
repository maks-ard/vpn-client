package main

import (
	"os"
	"path/filepath"

	"github.com/maks-ard/vpn-client/internal/app"
	"golang.org/x/sys/windows/registry"
)

// Поиск выполняет окно с правами пользователя, не служба SYSTEM.
func (s *Service) FindOVPN() []app.OVPNCandidate {
	var roots []string
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, "OpenVPN", "config"))
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
		if base := os.Getenv(env); base != "" {
			for _, dir := range []string{"config", "config-auto"} {
				roots = append(roots, filepath.Join(base, "OpenVPN", dir))
			}
		}
	}
	for _, location := range []struct {
		key   registry.Key
		path  string
		names []string
	}{
		{registry.CURRENT_USER, `SOFTWARE\OpenVPN-GUI`, []string{"config_dir"}},
		{registry.LOCAL_MACHINE, `SOFTWARE\OpenVPN`, []string{"config_dir", "auto_config_dir"}},
	} {
		for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
			key, err := registry.OpenKey(location.key, location.path, registry.QUERY_VALUE|view)
			if err != nil {
				continue
			}
			for _, name := range location.names {
				value, _, err := key.GetStringValue(name)
				if err != nil || value == "" {
					continue
				}
				if expanded, err := registry.ExpandString(value); err == nil {
					value = expanded
				}
				if filepath.IsAbs(value) {
					roots = append(roots, value)
				}
			}
			key.Close()
		}
	}
	return app.FindOVPN(roots)
}
