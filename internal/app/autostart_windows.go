package app

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

const taskName = "vpn-client"

// SetAutostart включает запуск при входе в Windows. Программа требует прав
// администратора, а ключ Run в реестре такие программы молча не запускает,
// поэтому используется задача планировщика с наивысшими правами.
func SetAutostart(enabled bool) error {
	if !enabled {
		out, err := schtasks("/Delete", "/F", "/TN", taskName)
		if err != nil && !strings.Contains(out, "cannot find") && !strings.Contains(out, "не удается найти") {
			return fmt.Errorf("отключение автозапуска: %s", strings.TrimSpace(out))
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	out, err := schtasks("/Create", "/F", "/TN", taskName, "/SC", "ONLOGON", "/RL", "HIGHEST",
		"/TR", fmt.Sprintf(`"%s" --autostart`, exe))
	if err != nil {
		return fmt.Errorf("включение автозапуска: %s", strings.TrimSpace(out))
	}
	return nil
}

func schtasks(args ...string) (string, error) {
	cmd := exec.Command("schtasks.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// OpenFile открывает файл в связанной программе (журнал — в Блокноте).
func OpenFile(path string) error {
	cmd := exec.Command("notepad.exe", path)
	return cmd.Start()
}
