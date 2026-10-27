package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/maks-ard/vpn-client/internal/openvpn"
	"github.com/maks-ard/vpn-client/internal/ovpn"
	"github.com/maks-ard/vpn-client/internal/singbox"
)

// Системный OpenVPN (Settings.SystemOpenVPN): корпоративную сеть поднимает
// openvpn.exe, установленный пользователем, а sing-box отправляет в его
// адаптер корпоративные домены и подсети. OpenVPN живёт всю сессию: перезапуск
// sing-box его не трогает, а свои обрывы он переживает сам.

const (
	// corpStartWait — сколько ждать OpenVPN перед запуском sing-box. Без
	// подключённого OpenVPN неизвестны адаптер и DNS компании; если он не
	// успел, sing-box запускается без них, а когда OpenVPN подключится,
	// перезапускается.
	corpStartWait = 15 * time.Second
	// resolveTimeout — сколько ждать адресов серверов OpenVPN из .ovpn.
	resolveTimeout = 5 * time.Second
)

var errCorpChanged = errors.New("у OpenVPN новое подключение")

type systemVPN struct {
	m      *Manager
	exe    string
	cancel context.CancelFunc

	mu   sync.Mutex
	link *openvpn.Link
	// servers — адреса серверов из .ovpn: их трафик идёт мимо TUN ещё до
	// первого подключения.
	servers []netip.Addr
	// changed получает сигнал, когда OpenVPN подключился.
	changed chan struct{}
	done    chan struct{}
}

// openVPNExe — openvpn.exe для системного режима.
func (m *Manager) openVPNExe() (string, error) {
	if m.openVPNPath != "" {
		return m.openVPNPath, nil
	}
	return openvpn.Find()
}

// systemVPNFor запускает системный OpenVPN, если он выбран в настройках и
// профиль OpenVPN загружен.
func (m *Manager) systemVPNFor(ctx context.Context, settings Settings) (*systemVPN, error) {
	if !settings.SystemOpenVPN {
		return nil, nil
	}
	if _, err := os.Stat(m.paths.ovpnFile()); err != nil {
		return nil, nil
	}
	// Без установленного OpenVPN корпоративная сеть не должна пропасть:
	// работает встроенный в sing-box.
	if _, err := m.openVPNExe(); err != nil {
		m.log.Printf("OpenVPN: %v; используется встроенный в sing-box", err)
		return nil, nil
	}
	return m.startSystemVPN(ctx, settings)
}

// startSystemVPN запускает OpenVPN до вызова stop или отмены ctx. Ошибки самого OpenVPN
// (сервер недоступен, отказ авторизации) не возвращаются, а видны в
// состоянии: VLESS из-за них не должен ломаться.
func (m *Manager) startSystemVPN(ctx context.Context, settings Settings) (*systemVPN, error) {
	exe, err := m.openVPNExe()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(m.paths.ovpnFile())
	if err != nil {
		return nil, fmt.Errorf("openvpn: %w", err)
	}
	cfg, err := ovpn.ParseFile(m.paths.ovpnFile())
	if err != nil {
		return nil, fmt.Errorf("openvpn: %w", err)
	}
	config, warnings, err := openvpn.Config(data, settings.OVPNUsername, settings.OVPNPassword)
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		m.log.Printf("OpenVPN: %s", w)
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &systemVPN{m: m, exe: exe, cancel: cancel, servers: resolveRemotes(ctx, cfg),
		changed: make(chan struct{}, 1), done: make(chan struct{})}
	// При включённом kill switch OpenVPN должен достучаться до сервера ещё до
	// запуска sing-box.
	m.guardCorp(exe, netip.Addr{})
	m.mu.Lock()
	m.system = s
	m.mu.Unlock()
	m.log.Printf("OpenVPN: запуск %s", exe)
	go s.run(ctx, config)
	return s, nil
}

// resolveRemotes находит адреса серверов из .ovpn. Ошибки не мешают: адрес
// сервера, к которому OpenVPN подключился, известен из его журнала.
func resolveRemotes(ctx context.Context, cfg *ovpn.Config) []netip.Addr {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	var out []netip.Addr
	for _, r := range cfg.Remotes {
		addrs := []netip.Addr{}
		if a, err := netip.ParseAddr(r.Host); err == nil {
			addrs = append(addrs, a)
		} else if found, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", r.Host); err == nil {
			addrs = found
		}
		for _, a := range addrs {
			if a = a.Unmap(); !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	return out
}

// run держит OpenVPN запущенным, пока не отменят ctx. Сбой при подключении
// повторяется не больше maxCorpRetries раз подряд, как и со встроенным OpenVPN.
func (s *systemVPN) run(ctx context.Context, config []byte) {
	defer close(s.done)
	for ctx.Err() == nil {
		authFailed := false
		proc, err := openvpn.Start(openvpn.Options{
			Exe: s.exe, Config: config, Dir: s.m.paths.Data, Output: s.m.log,
			OnEvent: func(ev openvpn.Event) {
				if ev.Kind == openvpn.EventAuthFailed {
					authFailed = true
				}
				s.handle(ev)
			},
		})
		if err != nil {
			s.m.log.Printf("OpenVPN: %v", err)
			s.m.update(func(st *State) { st.Corp.Up, st.Corp.Detail = false, shortError(err) })
			return
		}
		select {
		case <-ctx.Done():
			proc.Stop()
			return
		case <-proc.Done():
		}
		s.setLink(nil)
		reason := proc.Err().Error() + s.m.log.tailHint()
		detail := shortError(proc.Err())
		if authFailed {
			reason, detail = corpAuthFailed, corpAuthFailed
		}
		s.m.log.Printf("OpenVPN: %s", reason)
		s.m.update(func(st *State) { st.Corp.Up, st.Corp.Detail = false, detail })
		if authFailed {
			s.m.healthWarning("OpenVPN:", true, "OpenVPN: "+corpAuthFailed)
		}
		if !s.m.allowCorpRetry() {
			s.m.Logf("OpenVPN: %d перезапуска подряд не помогли, повторы остановлены до следующего подключения", maxCorpRetries)
			<-ctx.Done()
			return
		}
		sleep(ctx, reconnectDelay)
	}
}

func (s *systemVPN) handle(ev openvpn.Event) {
	switch ev.Kind {
	case openvpn.EventUp:
		l := ev.Link
		s.m.log.Printf("OpenVPN: подключено через %q, адрес %s, DNS %v, доменов %d, подсетей %d",
			l.Interface, l.Local, l.DNS, len(l.Domains), len(l.Routes))
		if l.Interface == "" {
			s.m.log.Printf("OpenVPN: имя адаптера не найдено в журнале, корпоративные домены недоступны")
		}
		s.m.mu.Lock()
		s.m.corpRetries = 0
		s.m.mu.Unlock()
		s.m.healthWarning("OpenVPN:", false, "")
		s.m.guardCorp(s.exe, l.Local)
		s.setLink(l)
	case openvpn.EventDown:
		s.m.update(func(st *State) { st.Corp.Up, st.Corp.Detail = false, corpReconnecting })
		s.setLink(nil)
	case openvpn.EventAuthFailed:
		s.m.update(func(st *State) { st.Corp.Up, st.Corp.Detail = false, corpAuthFailed })
	}
}

func (s *systemVPN) setLink(l *openvpn.Link) {
	s.mu.Lock()
	s.link = l
	s.mu.Unlock()
	if l != nil {
		select {
		case s.changed <- struct{}{}:
		default:
		}
	}
}

// Link — текущее подключение; nil — OpenVPN подключается.
func (s *systemVPN) Link() *openvpn.Link {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.link
}

// wait ждёт подключения OpenVPN не дольше d.
func (s *systemVPN) wait(ctx context.Context, d time.Duration) *openvpn.Link {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		if l := s.Link(); l != nil {
			return l
		}
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			return nil
		case <-s.done:
			return nil
		case <-s.changed:
		}
	}
}

// corpLink — что передать в конфиг sing-box для подключения l (nil — ещё
// не подключился).
func (s *systemVPN) corpLink(l *openvpn.Link) *singbox.CorpLink {
	c := &singbox.CorpLink{Servers: slices.Clone(s.servers)}
	if l == nil {
		return c
	}
	c.Interface, c.DNS, c.Domains, c.Routes = l.Interface, l.DNS, l.Domains, l.Routes
	if l.Server.IsValid() && !slices.Contains(c.Servers, l.Server) {
		c.Servers = append(c.Servers, l.Server)
	}
	return c
}

// stop останавливает OpenVPN и ждёт, пока он уберёт свои маршруты.
func (s *systemVPN) stop() {
	s.cancel()
	<-s.done
	s.m.mu.Lock()
	if s.m.system == s {
		s.m.system = nil
	}
	s.m.mu.Unlock()
	s.m.guardCorp("", netip.Addr{})
}
