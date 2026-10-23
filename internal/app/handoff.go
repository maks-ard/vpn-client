package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/maks-ard/vpn-client/internal/runner"
	"github.com/maks-ard/vpn-client/internal/singboxbin"
)

// Handoff — работающий sing-box, который служба при обновлении оставляет
// своей новой версии, чтобы не рвать соединения пользователя.
type Handoff struct {
	Process runner.Handoff `json:"process"`
	Session sessionInfo    `json:"session"`
	State   State          `json:"state"`
}

type handoffReply struct {
	handoff Handoff
	err     error
}

// В файле секрет Clash API: он лежит рядом с настройками, куда есть доступ
// только у системы и администраторов.
func (p Paths) handoffFile() string { return filepath.Join(p.Data, "handoff.json") }

// HandOff отпускает подключённый sing-box и записывает, как его найти.
// Возвращает имя job: его должен держать открытым процесс, перезапускающий
// службу, пока новая версия не вызовет Adopt, иначе Windows завершит sing-box.
func (m *Manager) HandOff() (string, error) {
	m.maintenance.Lock()
	defer m.maintenance.Unlock()
	m.mu.Lock()
	active, connected, done := m.cancel != nil, m.state.Status == StatusConnected, m.done
	m.mu.Unlock()
	if !active || !connected {
		return "", errors.New("VPN не подключён")
	}
	reply := make(chan handoffReply, 1)
	select {
	case m.handoffCh <- reply:
	case <-done:
		return "", errors.New("VPN отключился")
	case <-time.After(5 * time.Second):
		return "", errors.New("VPN сейчас переподключается")
	}
	r := <-reply
	if r.err != nil {
		return "", r.err
	}
	<-done
	m.mu.Lock()
	m.handedOff = true
	m.mu.Unlock()

	data, err := json.Marshal(r.handoff)
	if err == nil {
		err = os.WriteFile(m.paths.handoffFile(), data, 0o600)
	}
	if err != nil {
		// Без файла новая версия sing-box не найдёт: берём его обратно.
		if adoptErr := m.adopt(r.handoff); adoptErr != nil {
			return "", errors.Join(fmt.Errorf("передача sing-box: %w", err), adoptErr)
		}
		return "", fmt.Errorf("передача sing-box: %w", err)
	}
	return r.handoff.Process.Job, nil
}

// Adopt берёт под управление sing-box, оставленный прошлой версией службы
// (или этой же, если обновление не удалось). false — передачи не было.
// При ошибке VPN нужно подключить заново.
func (m *Manager) Adopt() (bool, error) {
	data, err := os.ReadFile(m.paths.handoffFile())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	// Файл одноразовый: после сбоя процесс по старому PID искать нельзя.
	_ = os.Remove(m.paths.handoffFile())
	if err != nil {
		return true, fmt.Errorf("передача sing-box: %w", err)
	}
	var h Handoff
	if err := json.Unmarshal(data, &h); err != nil {
		return true, fmt.Errorf("передача sing-box: %w", err)
	}
	m.maintenance.Lock()
	defer m.maintenance.Unlock()
	return true, m.adopt(h)
}

// adopt вызывается под maintenance.
func (m *Manager) adopt(h Handoff) error {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return errors.New("VPN уже подключён")
	}
	m.mu.Unlock()

	exe := m.singBoxPath
	if exe == "" {
		exe = runner.Path(m.paths.Data)
	}
	proc, err := runner.Adopt(h.Process, exe)
	if err != nil {
		m.mu.Lock()
		m.handedOff = false
		m.mu.Unlock()
		return err
	}
	unlock, err := m.openSingBox()
	if err != nil {
		// В новой версии другой sing-box: работающий останавливаем корректно,
		// чтобы он убрал маршруты, и подключаемся заново.
		proc.Stop()
		m.mu.Lock()
		m.handedOff = false
		m.mu.Unlock()
		return fmt.Errorf("sing-box обновился, нужно переподключение: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.cancel = cancel
	m.done = make(chan struct{})
	m.handedOff = false
	m.corpRetries = 0
	settings := m.settings
	h.State.Service = ""
	m.state = cloneState(h.State)
	state, done := m.state, m.done
	m.mu.Unlock()
	m.notify(state)
	m.log.Printf("подхвачен работающий sing-box (pid %d), соединения сохранены", h.Process.PID)

	live := &liveSession{
		proc: proc, api: newClash(h.Session.APIAddr, h.Session.APISecret), output: newSessionOutput(m),
		info: h.Session, adopted: true, unlock: unlock,
	}
	go m.run(ctx, settings, done, live)
	return nil
}

// openSingBox проверяет, что распакованный sing-box совпадает со встроенным
// в эту сборку, и не даёт подменить файл, пока процесс работает.
func (m *Manager) openSingBox() (func(), error) {
	if m.singBoxPath != "" {
		return func() {}, nil
	}
	data := singboxbin.Data()
	if data == nil {
		return nil, errors.New("в эту сборку не встроен sing-box")
	}
	_, release, err := runner.Open(m.paths.Data, data)
	return release, err
}

// streamLogs пишет журнал sing-box из Clash API в формате его stdout.
func (m *Manager) streamLogs(ctx context.Context, api *clash, level string, w io.Writer) {
	for ctx.Err() == nil {
		_ = api.logs(ctx, level, func(l clashLog) {
			fmt.Fprintf(w, "%s %s %s\n", time.Now().Format("-0700 2006-01-02 15:04:05"), strings.ToUpper(l.Type), l.Payload)
		})
		sleep(ctx, time.Second)
	}
}
