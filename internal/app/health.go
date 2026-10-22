package app

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/maks-ard/vpn-client/internal/singbox"
)

var serviceProbes = []struct{ name, url string }{
	{"YouTube", singbox.URLTestURL},
	{"Instagram", "https://www.instagram.com/"},
	{"ChatGPT", "https://chatgpt.com/"},
	{"Claude", "https://claude.ai/"},
}

type ServiceCheck struct {
	Name      string    `json:"name"`
	OK        bool      `json:"ok"`
	Delay     int       `json:"delay"`
	CheckedAt time.Time `json:"checkedAt"`
}

// Каждый сервис проверяется отдельно: успех YouTube не означает доступность остальных.
// Возвращает false, если через прокси не открылся ни один сервис.
func (m *Manager) checkServices(ctx context.Context, api *clash) bool {
	checks := probeServices(ctx, api, singbox.TagProxy)
	if ctx.Err() != nil {
		return true
	}
	ok := false
	for _, check := range checks {
		ok = ok || check.OK
		m.healthWarning(check.Name+":", !check.OK, check.Name+": проверка доступа через прокси не прошла")
	}
	m.update(func(s *State) { s.Proxy.Checks = checks })
	return ok
}

func probeServices(ctx context.Context, api *clash, outbound string) []ServiceCheck {
	var workers sync.WaitGroup
	checks := make([]ServiceCheck, len(serviceProbes))
	for i, probe := range serviceProbes {
		workers.Add(1)
		go func() {
			defer workers.Done()
			probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			delay, err := api.delayURL(probeCtx, outbound, probe.url)
			checks[i] = ServiceCheck{Name: probe.name, OK: err == nil, Delay: delay, CheckedAt: time.Now()}
		}()
	}
	workers.Wait()
	return checks
}

// bestServer прогоняет проверки сервисов через каждый сервер и выбирает тот,
// через который открывается больше сервисов, а при равенстве — с меньшей
// суммарной задержкой. Задержка до одного YouTube (как в urltest) не говорит,
// откроются ли остальные сайты. Пустая строка — ни один сервер не работает.
func bestServer(ctx context.Context, api *clash, servers []string) string {
	type score struct{ ok, delay int }
	scores := make([]score, len(servers))
	var workers sync.WaitGroup
	for i, server := range servers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for _, check := range probeServices(ctx, api, server) {
				if check.OK {
					scores[i].ok++
					scores[i].delay += check.Delay
				}
			}
		}()
	}
	workers.Wait()
	best := -1
	for i, s := range scores {
		if s.ok > 0 && (best < 0 || s.ok > scores[best].ok || s.ok == scores[best].ok && s.delay < scores[best].delay) {
			best = i
		}
	}
	if best < 0 {
		return ""
	}
	return servers[best]
}

const corpAuthFailed = "сервер OpenVPN отклонил авторизацию; проверьте учётные данные и параллельные подключения"

// sessionOutput разбирает только завершённые строки текущего процесса:
// сообщения OpenVPN не должны теряться среди ошибок DNS или оставаться от прошлой сессии.
type sessionOutput struct {
	m    *Manager
	mu   sync.Mutex
	part string

	// corpDown закрывается, когда endpoint OpenVPN завершился окончательно:
	// sing-box сам его уже не поднимет, нужен перезапуск сессии.
	corpDown     chan struct{}
	corpDownOnce sync.Once
	authFailed   bool
}

func newSessionOutput(m *Manager) *sessionOutput {
	return &sessionOutput{m: m, corpDown: make(chan struct{})}
}

// corpTerminated сообщает, что OpenVPN завершился, и было ли это отказом авторизации.
func (o *sessionOutput) corpTerminated() (bool, bool) {
	select {
	case <-o.corpDown:
		o.mu.Lock()
		defer o.mu.Unlock()
		return true, o.authFailed
	default:
		return false, false
	}
}

func (o *sessionOutput) Write(p []byte) (int, error) {
	n, err := o.m.log.Write(p)
	o.mu.Lock()
	lines := strings.Split(o.part+string(p), "\n")
	o.part = lines[len(lines)-1]
	if len(o.part) > 64<<10 {
		o.part = ""
	}
	o.mu.Unlock()
	for _, line := range lines[:len(lines)-1] {
		if !strings.Contains(line, "endpoint/openvpn-client[corp]") {
			continue
		}
		auth := strings.Contains(line, "authentication failed")
		if auth {
			o.m.update(func(s *State) {
				s.Corp.Up = false
				s.Corp.Detail = corpAuthFailed
			})
			o.m.healthWarning("OpenVPN:", true, "OpenVPN: "+corpAuthFailed)
		}
		if strings.Contains(line, "client terminated") && o.corpDown != nil {
			o.mu.Lock()
			o.authFailed = o.authFailed || auth
			o.mu.Unlock()
			o.corpDownOnce.Do(func() { close(o.corpDown) })
		}
	}
	return n, err
}

func (m *Manager) healthWarning(prefix string, failed bool, message string) {
	changed := false
	m.update(func(s *State) {
		warnings := make([]string, 0, len(s.Warnings)+1)
		found := false
		for _, w := range s.Warnings {
			if strings.HasPrefix(w, prefix) {
				found = true
			} else {
				warnings = append(warnings, w)
			}
		}
		if failed {
			warnings = append(warnings, message)
		}
		changed = found != failed
		s.Warnings = warnings
	})
	if changed {
		if failed {
			m.Logf("проверка связи: %s", message)
		} else {
			m.Logf("проверка связи: %s доступ восстановлен", prefix)
		}
	}
}
