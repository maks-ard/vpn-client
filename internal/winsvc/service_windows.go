// Package winsvc — служба Windows «vpn-client»: держит sing-box с правами
// системы, принимает команды окна по named pipe и сама обновляется.
package winsvc

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
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
	return app.Paths{Config: filepath.Join(root, "config"), Data: filepath.Join(root, "data"), Logs: LogDir()}
}

// LogDir — журнал службы. Его, в отличие от остальных данных, могут читать
// пользователи: окно открывает журнал, даже когда служба не отвечает.
func LogDir() string { return filepath.Join(DataRoot(), "logs") }

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
	pending  *pendingUpdate
	status   string
	statusMu sync.Mutex
}

type pendingUpdate struct {
	release   *update.Release
	path      string
	idleSince time.Time
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
	secErr := secureDir(DataRoot())
	logErr := secureLogDir(LogDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var m *app.Manager
	srv := ipc.NewServer(h.info, func() { h.tryUpdate(ctx, m) })
	m, _ = app.NewManager(paths, srv.Broadcast)
	srv.SetManager(m)
	m.Logf("служба запускается, версия %s", h.version)
	if secErr != nil {
		m.Logf("служба: права на %s: %v", DataRoot(), secErr)
	}
	if logErr != nil {
		m.Logf("служба: права на %s: %v", LogDir(), logErr)
	}
	defer func() {
		if r := recover(); r != nil {
			m.Logf("служба: паника: %v\n%s", r, debug.Stack())
			panic(r)
		}
	}()

	var listenerMu sync.Mutex
	var listener net.Listener
	go func() {
		defer recoverLog(m, "канал для окна")
		// Канал пересоздаётся, если сервер по какой-то причине остановился:
		// без него окно не может управлять службой.
		for ctx.Err() == nil {
			l, err := ipc.Listen()
			if err != nil {
				m.Logf("служба: не удалось открыть канал для окна: %v", err)
				sleepCtx(ctx, 3*time.Second)
				continue
			}
			listenerMu.Lock()
			listener = l
			listenerMu.Unlock()
			m.Logf("служба: канал для окна открыт")
			err = ipc.Serve(l, srv.Handler())
			_ = l.Close()
			if ctx.Err() != nil {
				return
			}
			m.Logf("служба: канал для окна закрылся (%v), открываю заново", err)
			sleepCtx(ctx, time.Second)
		}
	}()

	if resume := consumeResumeFlag(paths); resume || m.Settings().ConnectOnStart {
		go func() {
			defer recoverLog(m, "автоподключение")
			connectWithRetry(ctx, m)
		}()
	}
	go func() {
		defer recoverLog(m, "обновление")
		h.updateLoop(ctx, m)
	}()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent}
	m.Logf("служба запущена")
	for req := range requests {
		switch req.Cmd {
		case svc.Interrogate:
			status <- req.CurrentStatus
		case svc.PowerEvent:
			// PBT_APMRESUMEAUTOMATIC/PBT_APMRESUMESUSPEND: не пересоздаём
			// TUN из-за пробуждения, сначала обновляем состояние соединения.
			if req.EventType == 0x12 || req.EventType == 0x07 {
				go func() {
					defer recoverLog(m, "проверка после сна")
					m.Logf("Windows возобновила работу: проверка соединения")
					sleepCtx(ctx, 5*time.Second)
					if ctx.Err() == nil && m.Active() {
						m.TestServers()
					}
				}()
			}
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			cancel()
			m.DisconnectWithReason("остановка службы Windows")
			listenerMu.Lock()
			if listener != nil {
				_ = listener.Close()
			}
			listenerMu.Unlock()
			m.Logf("служба остановлена")
			return false, 0
		}
	}
	cancel()
	m.DisconnectWithReason("завершение обработчика службы")
	return false, 0
}

// recoverLog пишет панику горутины в журнал перед падением службы
// (Windows перезапустит её по настройкам восстановления).
func recoverLog(m *app.Manager, what string) {
	if r := recover(); r != nil {
		m.Logf("служба: паника (%s): %v\n%s", what, r, debug.Stack())
		panic(r)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
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
	// Проверка готового обновления не зависит от шестичасового опроса GitHub.
	go func() {
		defer recoverLog(m, "ожидание установки обновления")
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.updateMu.Lock()
				if ctx.Err() == nil {
					h.applyPending(m)
				}
				h.updateMu.Unlock()
			}
		}
	}()
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
	if h.pending != nil {
		h.applyPending(m)
		return
	}
	h.setStatus("Проверка обновлений…")
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
		h.setStatus("Ошибка загрузки обновления; подробности в журнале")
		m.Logf("обновление: %v", err)
		return
	}
	if ctx.Err() != nil {
		return
	}
	h.pending = &pendingUpdate{release: rel, path: path}
	h.applyPending(m)
}

// Вызывается под updateMu; после ошибки автоматические повторы прекращаются.
func (h *handler) applyPending(m *app.Manager) {
	if h.pending == nil {
		return
	}
	pending := h.pending
	if m.Active() {
		pending.idleSince = time.Time{}
		h.setStatus("Обновление " + pending.release.Version + " готово. Установится после отключения VPN")
		return
	}
	// Не принимаем короткий промежуток между отключением и подключением
	// при сохранении маршрутов за намеренное завершение VPN пользователем.
	if pending.idleSince.IsZero() {
		pending.idleSince = time.Now()
		return
	}
	if time.Since(pending.idleSince) < 5*time.Second {
		return
	}
	attempted, err := m.InstallWhileIdle(func() error {
		return h.installUpdate(m, pending.release, pending.path)
	})
	if !attempted {
		h.setStatus("Обновление " + pending.release.Version + " готово. Установится после отключения VPN")
		return
	}
	h.pending = nil
	if err != nil {
		h.setStatus("Не удалось установить обновление; повторите проверку. Подробности в журнале")
		m.Logf("обновление: %v", err)
	}
}

func (h *handler) installUpdate(m *app.Manager, rel *update.Release, path string) error {
	exe, err := os.Executable()
	if err != nil {
		h.setStatus("Ошибка определения установленного exe")
		m.Logf("обновление: %v", err)
		return err
	}
	if err := update.Replace(exe, path); err != nil {
		h.setStatus("Не удалось установить обновление; подробности в журнале")
		m.Logf("обновление: %v", err)
		return err
	}
	h.setStatus("Перезапуск после обновления до " + rel.Version)
	m.Logf("обновление: установлена %s, перезапуск службы", rel.Version)
	if err := startDetached(exe, "--restart-service"); err != nil {
		h.setStatus("Обновление записано, но перезапуск службы не запущен")
		m.Logf("обновление: перезапуск службы: %v", err)
		return fmt.Errorf("перезапуск службы: %w", err)
	}
	return nil
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
