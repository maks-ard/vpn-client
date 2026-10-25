package app

import (
	"net/netip"
	"os"
	"strings"

	"github.com/maks-ard/vpn-client/internal/killswitch"
	"github.com/maks-ard/vpn-client/internal/runner"
	"github.com/maks-ard/vpn-client/internal/singbox"
)

// Kill switch держится всё время, пока VPN включён: от запуска sing-box до
// отключения пользователем или ошибки, после которой повторов не будет.
// Обрыв и перезапуск sing-box, переподключение после изменения настроек
// блокировку не снимают.

// firewall — включённый kill switch; в тестах подменяется.
type firewall interface {
	Update(killswitch.Rules) error
	Close() error
}

func enableFirewall(rules killswitch.Rules) (firewall, error) {
	fw, err := killswitch.Enable(rules)
	if err != nil {
		return nil, err
	}
	return fw, nil
}

const killSwitchWarning = "Kill switch:"

// guard включает kill switch для сессии с sing-box exe или обновляет его
// разрешения.
func (m *Manager) guard(exe string) {
	m.guardMu.Lock()
	defer m.guardMu.Unlock()
	m.guardExe = exe
	m.syncGuard()
}

// refreshGuard применяет переключатель из настроек к идущей сессии.
func (m *Manager) refreshGuard() {
	m.guardMu.Lock()
	defer m.guardMu.Unlock()
	if m.guardExe != "" {
		m.syncGuard()
	}
}

// unguard снимает блокировку в конце сессии. Во время переподключения
// (keepGuard) блокировка остаётся до следующей сессии; возвращает, включена ли она.
func (m *Manager) unguard() bool {
	m.guardMu.Lock()
	defer m.guardMu.Unlock()
	m.guardExe = ""
	if !m.keepGuard && m.firewall != nil {
		m.closeGuard()
	}
	return m.firewall != nil
}

// Вызывается под guardMu.
func (m *Manager) syncGuard() {
	if !m.Settings().KillSwitch {
		if m.firewall != nil {
			m.closeGuard()
		}
		m.setKillSwitchWarning("")
		return
	}
	rules := m.guardRules()
	var err error
	if m.firewall != nil {
		err = m.firewall.Update(rules)
	} else if m.firewall, err = m.newFirewall(rules); err == nil {
		m.log.Printf("kill switch включён: без VPN соединения в интернет блокируются")
	}
	if err != nil {
		m.log.Printf("%v", err)
		m.setKillSwitchWarning(killSwitchWarning + " не удалось включить блокировку, при обрыве VPN трафик пойдёт напрямую")
	} else {
		m.setKillSwitchWarning("")
	}
	on := m.firewall != nil
	m.update(func(s *State) { s.KillSwitch = on })
}

// Вызывается под guardMu.
func (m *Manager) closeGuard() {
	if err := m.firewall.Close(); err != nil {
		m.log.Printf("%v", err)
	}
	m.firewall = nil
	m.log.Printf("kill switch выключен")
	m.update(func(s *State) { s.KillSwitch = false })
}

func (m *Manager) guardRules() killswitch.Rules {
	rules := killswitch.Rules{Tunnel: []netip.Addr{singbox.TunAddress4.Addr(), singbox.TunAddress6.Addr()}}
	// Служба сама скачивает подписку и наборы правил, в том числе пока VPN лежит.
	if self, err := os.Executable(); err == nil {
		rules.Apps = append(rules.Apps, self)
	}
	if m.guardExe != "" {
		rules.Apps = append(rules.Apps, m.guardExe)
	}
	return rules
}

// singBoxExe — путь sing-box, который запустил бы m.singBox; нужен для
// подхваченного процесса, чей файл уже распакован.
func (m *Manager) singBoxExe() string {
	if m.singBoxPath != "" {
		return m.singBoxPath
	}
	return runner.Path(m.paths.Data)
}

// restart переподключает VPN, не снимая блокировку между сессиями.
func (m *Manager) restart(reason string) {
	m.guardMu.Lock()
	m.keepGuard = true
	m.guardMu.Unlock()
	m.DisconnectWithReason(reason)
	m.guardMu.Lock()
	m.keepGuard = false
	m.guardMu.Unlock()
	m.Connect()
	// Подключение могло не начаться (идёт обновление): тогда блокировку
	// держать некому.
	if !m.Active() {
		m.unguard()
	}
}

func (m *Manager) setKillSwitchWarning(message string) {
	m.update(func(s *State) {
		warnings := s.Warnings[:0:0]
		for _, w := range s.Warnings {
			if !strings.HasPrefix(w, killSwitchWarning) {
				warnings = append(warnings, w)
			}
		}
		if message != "" {
			warnings = append(warnings, message)
		}
		s.Warnings = warnings
	})
}
