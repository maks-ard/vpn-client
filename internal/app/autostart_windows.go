package app

import (
	"errors"
	"fmt"
	"os/exec"

	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValue = "vpn-client"

// SetAutostart включает запуск окна при входе пользователя в Windows.
// Окно работает без прав администратора, поэтому хватает ключа Run;
// сам VPN поднимает служба, она стартует вместе с системой.
func SetAutostart(enabled bool, exe string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("автозапуск: %w", err)
	}
	defer k.Close()
	if !enabled {
		if err := k.DeleteValue(runValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("автозапуск: %w", err)
		}
		return nil
	}
	return k.SetStringValue(runValue, fmt.Sprintf(`"%s" --autostart`, exe))
}

// OpenFile открывает текстовый файл в Блокноте.
func OpenFile(path string) error {
	return exec.Command("notepad.exe", path).Start()
}
