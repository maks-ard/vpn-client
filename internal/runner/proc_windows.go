package runner

import (
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// prepare запускает sing-box в отдельной группе процессов, чтобы Ctrl+C из
// консоли получал только vpnclient, а sing-box останавливался по нашей команде.
func prepare(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
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
func interrupt(cmd *exec.Cmd) error {
	return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(cmd.Process.Pid))
}

// IsElevated сообщает, запущен ли процесс с правами администратора.
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
