// Package winsvc — служба Windows «vpn-client»: держит sing-box с правами
// системы, принимает команды окна по named pipe и сама обновляется.
package winsvc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/maks-ard/vpn-client/internal/app"
	"github.com/maks-ard/vpn-client/internal/ipc"
	"github.com/maks-ard/vpn-client/internal/singboxbin"
	"github.com/maks-ard/vpn-client/internal/update"
)

const Name = "vpn-client"

// Paths — данные службы в %ProgramData%\vpn-client (доступ только у системы
// и администраторов, окно читает всё через API).
func Paths() app.Paths {
	root := DataRoot()
	return app.Paths{Config: filepath.Join(root, "config"), Data: filepath.Join(root, "data")}
}

func DataRoot() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "vpn-client")
}

// InstallDir — куда ставится программа.
func InstallDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "vpn-client")
}

func InstalledExe() string { return filepath.Join(InstallDir(), "vpnclient.exe") }

// IsService сообщает, запущен ли процесс менеджером служб.
func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// Run — точка входа процесса службы.
func Run(version string) error {
	return svc.Run(Name, &handler{version: version})
}

type handler struct {
	version string

	updateMu sync.Mutex
	status   string
	statusMu sync.Mutex
}

func (h *handler) info() ipc.Info {
	exe, _ := os.Executable()
	h.statusMu.Lock()
	defer h.statusMu.Unlock()
	return ipc.Info{Version: h.version, SingBox: singboxbin.Version, Exe: exe, Update: h.status}
}

func (h *handler) setStatus(s string) {
	h.statusMu.Lock()
	h.status = s
	h.statusMu.Unlock()
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	paths := Paths()
	_ = secureDir(DataRoot())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var m *app.Manager
	srv := ipc.NewServer(h.info, func() { h.tryUpdate(ctx, m) })
	m, _ = app.NewManager(paths, srv.Broadcast)
	srv.SetManager(m)

	l, err := ipc.Listen()
	if err != nil {
		m.Logf("служба: не удалось открыть канал для окна: %v", err)
		return false, 1
	}
	go func() {
		if err := ipc.Serve(l, srv.Handler()); err != nil {
			m.Logf("служба: канал для окна: %v", err)
		}
	}()

	m.Logf("служба запущена, версия %s", h.version)

	if resume := consumeResumeFlag(paths); resume || m.Settings().ConnectOnStart {
		go connectWithRetry(ctx, m)
	}
	go h.updateLoop(ctx, m)

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for req := range requests {
		switch req.Cmd {
		case svc.Interrogate:
			status <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			cancel()
			m.Disconnect()
			_ = l.Close()
			m.Logf("служба остановлена")
			return false, 0
		}
	}
	cancel()
	m.Disconnect()
	return false, 0
}

// connectWithRetry: при загрузке системы сеть появляется не сразу, поэтому
// неудачное подключение повторяем несколько раз.
func connectWithRetry(ctx context.Context, m *app.Manager) {
	for attempt := 0; attempt < 6 && ctx.Err() == nil; attempt++ {
		m.Connect()
		for ctx.Err() == nil {
			time.Sleep(time.Second)
			st := m.State().Status
			if st == app.StatusConnected || st == app.StatusDisconnected {
				return
			}
			if st == app.StatusError {
				break
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(20 * time.Second):
		}
	}
}

// Флаг «переподключиться после перезапуска»: ставится перед обновлением,
// если VPN был включён.
func resumeFile(p app.Paths) string { return filepath.Join(p.Data, "resume") }

func consumeResumeFlag(p app.Paths) bool {
	err := os.Remove(resumeFile(p))
	return err == nil
}

func (h *handler) updateLoop(ctx context.Context, m *app.Manager) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}
	for ctx.Err() == nil {
		h.tryUpdate(ctx, m)
		select {
		case <-ctx.Done():
		case <-time.After(6 * time.Hour):
		}
	}
}

// tryUpdate скачивает новую версию, ставит её на место текущего exe и
// перезапускает службу отдельным процессом.
func (h *handler) tryUpdate(ctx context.Context, m *app.Manager) {
	if !update.Valid(h.version) {
		return
	}
	h.updateMu.Lock()
	defer h.updateMu.Unlock()

	c := update.NewChecker()
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	rel, err := c.Latest(checkCtx)
	cancel()
	if err != nil {
		h.setStatus("не удалось проверить обновления")
		m.Logf("обновление: %v", err)
		return
	}
	if !update.Newer(rel.Version, h.version) {
		h.setStatus("обновлений нет, проверено в " + time.Now().Format("15:04"))
		return
	}
	m.Logf("обновление: загружаю %s", rel.Version)
	h.setStatus("Загружается " + rel.Version)
	path, err := c.Download(ctx, rel, filepath.Join(Paths().Data, "update"))
	if err != nil {
		h.setStatus("")
		m.Logf("обновление: %v", err)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		h.setStatus("")
		m.Logf("обновление: %v", err)
		return
	}
	if err := update.Replace(exe, path); err != nil {
		h.setStatus("")
		m.Logf("обновление: %v", err)
		return
	}
	if m.Active() {
		_ = os.WriteFile(resumeFile(Paths()), nil, 0o600)
	}
	h.setStatus("Перезапуск после обновления до " + rel.Version)
	m.Logf("обновление: установлена %s, перезапуск службы", rel.Version)
	if err := startDetached(exe, "--restart-service"); err != nil {
		m.Logf("обновление: перезапуск службы: %v", err)
	}
}

// startDetached запускает процесс, который переживёт остановку службы.
func startDetached(exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
