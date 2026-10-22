package winsvc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
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
	if err := secureLogDir(LogDir()); err != nil {
		return fmt.Errorf("права на %s: %w", LogDir(), err)
	}
	if err := s.Start(); err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return errors.New(AntivirusHint)
		}
		return fmt.Errorf("запуск службы: %w", err)
	}

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
	deadline := time.Now().Add(20 * time.Second)
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
	// Служба зависла и не реагирует на остановку — завершаем процесс.
	if st.ProcessId != 0 {
		if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, st.ProcessId); err == nil {
			_ = windows.TerminateProcess(h, 1)
			_, _ = windows.WaitForSingleObject(h, 10000)
			_ = windows.CloseHandle(h)
		}
		for i := 0; i < 20; i++ {
			time.Sleep(300 * time.Millisecond)
			if st, err = s.Query(); err == nil && st.State == svc.Stopped {
				return nil
			}
		}
	}
	return errors.New("служба не остановилась за 20 секунд")
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

// secureLogDir: журнал службы читают все пользователи, пишут — система и
// администраторы. Ссылка на подписку в журнале заменяется на ***.
func secureLogDir(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)")
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

// createShortcut кладёт ярлык в меню «Пуск» для всех пользователей через
// COM-объект WScript.Shell напрямую — без запуска PowerShell (скрытый
// PowerShell антивирусы справедливо считают признаком вредоноса).
func createShortcut(target string) error {
	// COM требует, чтобы горутина не переезжала между потоками.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		return err
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("WScript.Shell")
	if err != nil {
		return err
	}
	defer unknown.Release()
	shell, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return err
	}
	defer shell.Release()
	res, err := oleutil.CallMethod(shell, "CreateShortcut", shortcutPath())
	if err != nil {
		return err
	}
	link := res.ToIDispatch()
	defer link.Release()
	for name, value := range map[string]string{
		"TargetPath":       target,
		"WorkingDirectory": filepath.Dir(target),
		"Description":      "vpn-client",
	} {
		if _, err := oleutil.PutProperty(link, name, value); err != nil {
			return err
		}
	}
	_, err = oleutil.CallMethod(link, "Save")
	return err
}

// AntivirusHint — что сказать, если файл программы исчез сразу после
// установки: так бывает, когда антивирус удаляет его по ложному срабатыванию.
const AntivirusHint = "Файл программы в C:\\Program Files\\vpn-client пропал — вероятно, его удалил антивирус. " +
	"Восстановите его из карантина и добавьте в исключения антивируса папки " +
	"C:\\Program Files\\vpn-client и C:\\ProgramData\\vpn-client, затем нажмите кнопку ещё раз."

// ErrCancelled — пользователь отказался в окне UAC.
var ErrCancelled = errors.New("установка отменена в запросе прав администратора")

var (
	shell32                 = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW     = shell32.NewProc("ShellExecuteExW")
	user32                  = windows.NewLazySystemDLL("user32.dll")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
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
// завершения. Возвращает код выхода. owner — окно, поверх которого Windows
// покажет запрос: без него запрос часто открывается в фоне и только мигает
// на панели задач.
func RunElevated(owner uintptr, exe string, args string) (uint32, error) {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	params, err := windows.UTF16PtrFromString(args)
	if err != nil {
		return 0, err
	}
	if owner != 0 {
		// Запрос прав появится на переднем плане, только если наше окно сейчас активно.
		procSetForegroundWindow.Call(owner)
	}
	info := shellExecuteInfo{
		hwnd:         windows.Handle(owner),
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
