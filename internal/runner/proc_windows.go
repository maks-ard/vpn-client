package runner

import (
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleWindow  = kernel32.NewProc("GetConsoleWindow")
	procAttachConsole     = kernel32.NewProc("AttachConsole")
	procFreeConsole       = kernel32.NewProc("FreeConsole")
	procSetConsoleHandler = kernel32.NewProc("SetConsoleCtrlHandler")
)

func hasConsole() bool {
	h, _, _ := procGetConsoleWindow.Call()
	return h != 0
}

// prepare запускает sing-box в отдельной группе процессов, чтобы Ctrl+C из
// консоли получал только vpnclient, а sing-box останавливался по нашей команде.
// У GUI-приложения консоли нет, и sing-box запускается без окна.
func prepare(cmd *exec.Cmd) {
	flags := uint32(windows.CREATE_NEW_PROCESS_GROUP)
	if !hasConsole() {
		flags |= windows.CREATE_NO_WINDOW
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags, HideWindow: true}
}

// attach помещает sing-box в Job Object: если vpnclient упадёт, Windows сама
// завершит sing-box, и TUN с маршрутами не останутся висеть.
func attach(cmd *exec.Cmd) func() {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return func() {}
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err == nil {
		process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
		if err == nil {
			_ = windows.AssignProcessToJobObject(job, process)
			_ = windows.CloseHandle(process)
		}
	}
	return func() { _ = windows.CloseHandle(job) }
}

// interrupt посылает CTRL_BREAK группе процессов sing-box; Go-рантайм
// превращает его в os.Interrupt, и sing-box корректно завершается.
// Если своей консоли нет (GUI), на время подключаемся к скрытой консоли sing-box.
func interrupt(cmd *exec.Cmd) error {
	pid := uint32(cmd.Process.Pid)
	if hasConsole() {
		return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, pid)
	}
	if r, _, err := procAttachConsole.Call(uintptr(pid)); r == 0 {
		return err
	}
	defer procFreeConsole.Call()
	// Сами сигнал не обрабатываем: он адресован группе процессов sing-box.
	procSetConsoleHandler.Call(0, 1)
	defer procSetConsoleHandler.Call(0, 0)
	return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, pid)
}

// IsElevated сообщает, запущен ли процесс с правами администратора.
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

const isWindows = true

// openLocked открывает файл, запрещая другим процессам запись и удаление,
// пока дескриптор открыт. Запуск exe при этом разрешён.
func openLocked(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}
