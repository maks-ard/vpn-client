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
func (m *Manager) checkServices(ctx context.Context, api *clash) {
	var workers sync.WaitGroup
	checks := make([]ServiceCheck, len(serviceProbes))
	for i, probe := range serviceProbes {
		workers.Add(1)
		go func() {
			defer workers.Done()
			probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			delay, err := api.delayURL(probeCtx, singbox.TagProxy, probe.url)
			checks[i] = ServiceCheck{Name: probe.name, OK: err == nil, Delay: delay, CheckedAt: time.Now()}
			if ctx.Err() != nil {
				return
			}
			m.healthWarning(probe.name+":", err != nil, probe.name+": проверка доступа через прокси не прошла")
		}()
	}
	workers.Wait()
	if ctx.Err() == nil {
		m.update(func(s *State) { s.Proxy.Checks = checks })
	}
}

const corpAuthFailed = "сервер OpenVPN отклонил авторизацию; проверьте учётные данные и параллельные подключения"

// sessionOutput разбирает только завершённые строки текущего процесса:
// сообщения OpenVPN не должны теряться среди ошибок DNS или оставаться от прошлой сессии.
type sessionOutput struct {
	m    *Manager
	mu   sync.Mutex
	part string
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
		if strings.Contains(line, "endpoint/openvpn-client[corp]") && strings.Contains(line, "authentication failed") {
			o.m.update(func(s *State) {
				s.Corp.Up = false
				s.Corp.Detail = corpAuthFailed
			})
			o.m.healthWarning("OpenVPN:", true, "OpenVPN: "+corpAuthFailed)
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
