package runner

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
	procOpenJobObject     = kernel32.NewProc("OpenJobObjectW")
	procIsProcessInJob    = kernel32.NewProc("IsProcessInJob")
)

const jobObjectQuery = 0x0004

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

// osProcess держит sing-box в Job Object: если служба упадёт, Windows сама
// завершит sing-box, и TUN с маршрутами не останутся висеть. У job есть имя,
// чтобы при обновлении новая версия службы могла открыть его до выхода старой
// и sing-box продолжил работать.
type osProcess struct {
	mu      sync.Mutex
	pid     uint32
	job     windows.Handle
	jobName string
	process windows.Handle
	// cmd — свой процесс: убить его можно, даже если job не создался.
	cmd *os.Process
}

// Job доступен только системе и администраторам: открывший его может
// завершить sing-box или не дать ему завершиться.
const jobSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

func attach(cmd *exec.Cmd) *osProcess {
	o := &osProcess{pid: uint32(cmd.Process.Pid), cmd: cmd.Process}
	o.job, o.jobName = createJob()
	if o.job == 0 {
		return o
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	_, err := windows.SetInformationJobObject(o.job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		return o
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|
		windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, o.pid)
	if err != nil {
		return o
	}
	if windows.AssignProcessToJobObject(o.job, process) != nil {
		_ = windows.CloseHandle(process)
		return o
	}
	o.process = process
	return o
}

// createJob создаёт именованный job. Global\ с доступом только для системы и
// администраторов — для службы; без прав администратора (vpnctl, тесты) такой
// job не открыть даже создателю, поэтому берём пространство имён своего сеанса.
func createJob() (windows.Handle, string) {
	name := "vpn-client-sing-box-" + randomName()
	if sd, err := windows.SecurityDescriptorFromString(jobSDDL); err == nil && IsElevated() {
		sa := windows.SecurityAttributes{SecurityDescriptor: sd}
		sa.Length = uint32(unsafe.Sizeof(sa))
		if job, err := windows.CreateJobObject(&sa, windows.StringToUTF16Ptr(`Global\`+name)); err == nil {
			return job, `Global\` + name
		}
	}
	if job, err := windows.CreateJobObject(nil, windows.StringToUTF16Ptr(`Local\`+name)); err == nil {
		return job, `Local\` + name
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, ""
	}
	return job, ""
}

func randomName() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (o *osProcess) handoff() (Handoff, error) {
	if o.jobName == "" || o.process == 0 {
		return Handoff{}, errors.New("sing-box запущен без именованного job")
	}
	created, err := processCreated(o.process)
	if err != nil {
		return Handoff{}, err
	}
	return Handoff{Job: o.jobName, PID: int(o.pid), Created: created}, nil
}

// adopt открывает job и проверяет, что процесс с этим PID — тот самый sing-box:
// он в этом job, запущен в то же время и из ожидаемого файла.
func adopt(h Handoff, exe string) (*osProcess, error) {
	job, err := openJob(h.Job)
	if err != nil {
		return nil, err
	}
	o := &osProcess{pid: uint32(h.PID), job: job, jobName: h.Job}
	if err := o.verify(h, exe); err != nil {
		o.close()
		return nil, err
	}
	return o, nil
}

// HoldJob открывает job переданного sing-box: пока дескриптор открыт,
// Windows не завершит процесс, даже если его прежний владелец вышел.
func HoldJob(name string) (func(), error) {
	job, err := openJob(name)
	if err != nil {
		return nil, err
	}
	return func() { _ = windows.CloseHandle(job) }, nil
}

func openJob(name string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	r, _, err := procOpenJobObject.Call(jobObjectQuery|windows.SYNCHRONIZE, 0, uintptr(unsafe.Pointer(p)))
	if r == 0 {
		return 0, fmt.Errorf("job %s: %w", name, err)
	}
	return windows.Handle(r), nil
}

func (o *osProcess) verify(h Handoff, exe string) error {
	process, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE|
		windows.PROCESS_QUERY_LIMITED_INFORMATION, false, o.pid)
	if err != nil {
		return fmt.Errorf("процесс %d: %w", o.pid, err)
	}
	o.process = process
	var inJob int32
	if r, _, err := procIsProcessInJob.Call(uintptr(process), uintptr(o.job), uintptr(unsafe.Pointer(&inJob))); r == 0 {
		return fmt.Errorf("процесс %d: %w", o.pid, err)
	}
	if inJob == 0 {
		return fmt.Errorf("процесс %d не принадлежит job %s", o.pid, h.Job)
	}
	created, err := processCreated(process)
	if err != nil {
		return err
	}
	if created != h.Created {
		return fmt.Errorf("процесс %d запущен в другое время: это уже не sing-box", o.pid)
	}
	if exe == "" {
		return nil
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(process, 0, &buf[0], &size); err != nil {
		return fmt.Errorf("процесс %d: %w", o.pid, err)
	}
	if got := windows.UTF16ToString(buf[:size]); !strings.EqualFold(filepath.Clean(got), filepath.Clean(exe)) {
		return fmt.Errorf("процесс %d запущен из %s, а не из %s", o.pid, got, exe)
	}
	return nil
}

func processCreated(process windows.Handle) (int64, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(process, &created, &exited, &kernel, &user); err != nil {
		return 0, fmt.Errorf("время запуска sing-box: %w", err)
	}
	return created.Nanoseconds(), nil
}

func (o *osProcess) wait() (uint32, error) {
	if _, err := windows.WaitForSingleObject(o.process, windows.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	err := windows.GetExitCodeProcess(o.process, &code)
	return code, err
}

func (o *osProcess) kill() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.process == 0 {
		if o.cmd != nil {
			return o.cmd.Kill()
		}
		return errors.New("sing-box уже завершён")
	}
	return windows.TerminateProcess(o.process, 1)
}

func (o *osProcess) close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.process != 0 {
		_ = windows.CloseHandle(o.process)
		o.process = 0
	}
	if o.job != 0 {
		_ = windows.CloseHandle(o.job)
		o.job = 0
	}
}

// interrupt посылает CTRL_BREAK группе процессов sing-box; Go-рантайм
// превращает его в os.Interrupt, и sing-box корректно завершается.
// Если своей консоли нет (служба), на время подключаемся к скрытой консоли
// sing-box: так останавливается и процесс, запущенный прошлой версией службы.
func (o *osProcess) interrupt() error {
	if hasConsole() {
		return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, o.pid)
	}
	if r, _, err := procAttachConsole.Call(uintptr(o.pid)); r == 0 {
		return err
	}
	defer procFreeConsole.Call()
	// Сами сигнал не обрабатываем: он адресован группе процессов sing-box.
	procSetConsoleHandler.Call(0, 1)
	defer procSetConsoleHandler.Call(0, 0)
	return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, o.pid)
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
