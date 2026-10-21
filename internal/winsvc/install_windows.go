package winsvc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/maks-ard/vpn-client/internal/update"
)

// Install (с правами администратора) копирует программу в Program Files,
// создаёт или обновляет службу и запускает её.
func Install() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	target := InstalledExe()

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("диспетчер служб: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(Name)
	exists := err == nil
	if exists {
		defer s.Close()
		if err := stopAndWait(s); err != nil {
			return err
		}
	}

	if !samePath(self, target) {
		if err := os.MkdirAll(InstallDir(), 0o755); err != nil {
			return err
		}
		if err := copyExe(self, target); err != nil {
			return err
		}
	}

	cfg := mgr.Config{
		DisplayName:  "vpn-client",
		Description:  "VPN с раздельной маршрутизацией: OpenVPN для работы, VLESS для зарубежных сайтов.",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}
	if exists {
		current, err := s.Config()
		if err != nil {
			return err
		}
		current.DisplayName, current.Description = cfg.DisplayName, cfg.Description
		current.StartType = cfg.StartType
		current.BinaryPathName = fmt.Sprintf(`"%s" --service`, target)
		if err := s.UpdateConfig(current); err != nil {
			return fmt.Errorf("обновление службы: %w", err)
		}
	} else {
		s, err = m.CreateService(Name, target, cfg, "--service")
		if err != nil {
			return fmt.Errorf("создание службы: %w", err)
		}
		defer s.Close()
	}

	// Если служба упадёт, Windows перезапустит её сама.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, 24*60*60)

	if err := os.MkdirAll(DataRoot(), 0o700); err != nil {
		return err
	}
	if err := secureDir(DataRoot()); err != nil {
		return fmt.Errorf("права на %s: %w", DataRoot(), err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("запуск службы: %w", err)
	}

	// Версии 0.1.x запускали окно с правами администратора через планировщик.
	_ = hidden("schtasks.exe", "/Delete", "/F", "/TN", Name).Run()
	_ = createShortcut(target)
	return nil
}

// Uninstall удаляет службу и ярлык. Файлы программы остаются: запущенный
// exe удалить нельзя.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return nil
	}
	defer s.Close()
	_ = stopAndWait(s)
	if err := s.Delete(); err != nil {
		return err
	}
	_ = os.Remove(shortcutPath())
	return nil
}

// RestartService останавливает и снова запускает службу (после обновления).
func RestartService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := stopAndWait(s); err != nil {
		return err
	}
	return s.Start()
}

func stopAndWait(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("остановка службы: %w", err)
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		st, err = s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
	}
	return errors.New("служба не остановилась за 30 секунд")
}

func samePath(a, b string) bool {
	a, _ = filepath.Abs(a)
	b, _ = filepath.Abs(b)
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// copyExe ставит копию src на место dst, даже если dst сейчас запущен.
func copyExe(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return update.Replace(dst, tmp)
}

// secureDir оставляет доступ к данным службы только системе и
// администраторам: там настройки с паролями и распакованный sing-box.
func secureDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func shortcutPath() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs`, "vpn-client.lnk")
}

// createShortcut кладёт ярлык в меню «Пуск» для всех пользователей.
func createShortcut(target string) error {
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	script := fmt.Sprintf(
		"$s=(New-Object -ComObject WScript.Shell).CreateShortcut(%s);$s.TargetPath=%s;$s.WorkingDirectory=%s;$s.Description='vpn-client';$s.Save()",
		q(shortcutPath()), q(target), q(filepath.Dir(target)))
	return hidden("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script).Run()
}

func hidden(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

// ErrCancelled — пользователь отказался в окне UAC.
var ErrCancelled = errors.New("установка отменена в запросе прав администратора")

var (
	shell32             = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW = shell32.NewProc("ShellExecuteExW")
)

type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           windows.Handle
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       windows.Handle
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      windows.Handle
	dwHotKey       uint32
	hIconOrMonitor windows.Handle
	hProcess       windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoUI           = 0x00000400
)

// RunElevated запускает exe с правами администратора (запрос UAC) и ждёт
// завершения. Возвращает код выхода.
func RunElevated(exe string, args string) (uint32, error) {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	params, err := windows.UTF16PtrFromString(args)
	if err != nil {
		return 0, err
	}
	info := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess | seeMaskNoUI,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		nShow:        windows.SW_HIDE,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if r, _, err := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return 0, ErrCancelled
		}
		return 0, err
	}
	if info.hProcess == 0 {
		return 0, errors.New("не удалось запустить установку")
	}
	defer windows.CloseHandle(info.hProcess)
	if _, err := windows.WaitForSingleObject(info.hProcess, windows.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.hProcess, &code); err != nil {
		return 0, err
	}
	return code, nil
}

// ServiceRunning сообщает, установлена ли служба и запущена ли она.
func ServiceRunning() (installed, running bool) {
	m, err := mgr.Connect()
	if err != nil {
		// Без прав администратора подключиться к диспетчеру на запись нельзя,
		// пробуем только чтение.
		return queryReadOnly()
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return false, false
	}
	defer s.Close()
	st, err := s.Query()
	return true, err == nil && st.State == svc.Running
}

func queryReadOnly() (installed, running bool) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, false
	}
	defer windows.CloseServiceHandle(h)
	name, _ := windows.UTF16PtrFromString(Name)
	sh, err := windows.OpenService(h, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false, false
	}
	defer windows.CloseServiceHandle(sh)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(sh, &st); err != nil {
		return true, false
	}
	return true, st.CurrentState == windows.SERVICE_RUNNING
}
