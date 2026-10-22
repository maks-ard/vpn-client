package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/maks-ard/vpn-client/internal/runner"
	"github.com/maks-ard/vpn-client/internal/singbox"
	"github.com/maks-ard/vpn-client/internal/singboxbin"
)

type Status string

const (
	StatusDisconnected Status = "disconnected"
	StatusConnecting   Status = "connecting"
	StatusConnected    Status = "connected"
	StatusError        Status = "error"
)

// State — снимок состояния для окна и трея.
type State struct {
	Status      Status    `json:"status"`
	Error       string    `json:"error,omitempty"`
	ConnectedAt time.Time `json:"connectedAt,omitempty"`
	Up          int64     `json:"up"`   // байт/с
	Down        int64     `json:"down"` // байт/с

	Corp  CorpState  `json:"corp"`
	Proxy ProxyState `json:"proxy"`
	// Warnings — некритичные замечания (подписка из кэша, директивы .ovpn).
	Warnings []string `json:"warnings,omitempty"`
	// Service заполняет окно, когда со службой что-то не так:
	// "missing" — не установлена, "installing" — ставится, "unavailable" — не отвечает.
	Service string `json:"service,omitempty"`
}

type CorpState struct {
	Enabled bool   `json:"enabled"`
	Up      bool   `json:"up"`
	Detail  string `json:"detail"`
	Domains string `json:"domains"`
}

type ProxyState struct {
	Enabled bool `json:"enabled"`
	// Selected — выбор пользователя: "auto" или имя сервера.
	Selected string `json:"selected"`
	// Current — сервер, через который реально идёт трафик.
	Current string   `json:"current"`
	Delay   int      `json:"delay"` // мс, 0 — неизвестно
	Servers []Server `json:"servers"`

	Title    string    `json:"title,omitempty"`
	Used     int64     `json:"used,omitempty"`
	Total    int64     `json:"total,omitempty"`
	Expire   time.Time `json:"expire,omitempty"`
	Updated  time.Time `json:"updated,omitempty"`
	Outdated bool      `json:"outdated,omitempty"`
}

type Server struct {
	Name  string `json:"name"`
	Delay int    `json:"delay"`
}

// Manager управляет sing-box и хранит настройки. Безопасен для вызова из
// нескольких горутин (GUI, трей, таймеры).
type Manager struct {
	paths    Paths
	onChange func(State)
	log      *logFile

	// inbound заменяет TUN в тестах.
	inbound singbox.M
	// singBoxPath — внешний sing-box вместо встроенного (для разработки).
	singBoxPath string

	mu          sync.Mutex
	maintenance sync.Mutex
	settings    Settings
	state       State
	cancel      context.CancelFunc
	done        chan struct{}
	api         *clash
}

func NewManager(paths Paths, onChange func(State)) (*Manager, error) {
	s, err := loadSettings(paths)
	log := newLogFile(paths.LogFile())
	if err != nil {
		log.Printf("%v", err)
	}
	log.redact(s.Link)
	m := &Manager{paths: paths, onChange: onChange, log: log, settings: s, singBoxPath: os.Getenv("VPNCLIENT_SINGBOX")}
	m.state = m.idleState()
	return m, nil
}

func (m *Manager) Paths() Paths { return m.paths }

func (m *Manager) Settings() Settings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings
}

func (m *Manager) OVPN() OVPNInfo { return ovpnInfo(m.paths) }

// SaveSettings сохраняет настройки. Если VPN подключён и поменялось то,
// что влияет на маршруты, он переподключается.
func (m *Manager) SaveSettings(s Settings) error {
	if err := s.normalize(); err != nil {
		return err
	}
	m.mu.Lock()
	old := m.settings
	if s.Link != old.Link {
		s.Server = ""
	}
	if err := saveSettings(m.paths, s); err != nil {
		m.mu.Unlock()
		return err
	}
	m.settings = s
	m.log.redact(s.Link)
	active := m.cancel != nil
	if !active {
		m.state = m.idleState()
	}
	state := m.state
	m.mu.Unlock()
	m.notify(state)

	if active && routingChanged(old, s) {
		m.log.Printf("настройки изменены, переподключение")
		m.DisconnectWithReason("изменение настроек маршрутизации")
		m.Connect()
	}
	return nil
}

func routingChanged(a, b Settings) bool {
	return a.Link != b.Link || a.OVPNUsername != b.OVPNUsername || a.OVPNPassword != b.OVPNPassword ||
		a.RussiaDirect != b.RussiaDirect || strings.Join(a.CorpDomains, ",") != strings.Join(b.CorpDomains, ",")
}

// ImportOVPN сохраняет .ovpn, подготовленный PrepareOVPN.
func (m *Manager) ImportOVPN(name string, data []byte) (OVPNInfo, error) {
	info, err := importOVPN(m.paths, name, data)
	if err != nil {
		return OVPNInfo{}, err
	}
	m.reconnectIfActive("загружен новый .ovpn")
	return info, nil
}

func (m *Manager) RemoveOVPN() error {
	if err := removeOVPN(m.paths); err != nil {
		return err
	}
	m.reconnectIfActive(".ovpn удалён")
	return nil
}

func (m *Manager) reconnectIfActive(reason string) {
	m.mu.Lock()
	active := m.cancel != nil
	if !active {
		m.state = m.idleState()
	}
	state := m.state
	m.mu.Unlock()
	m.notify(state)
	if active {
		m.log.Printf("%s, переподключение", reason)
		m.DisconnectWithReason(reason)
		m.Connect()
	}
}

func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *Manager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cancel != nil
}

// Toggle подключает или отключает VPN.
func (m *Manager) Toggle() {
	if m.Active() {
		m.Disconnect()
	} else {
		m.Connect()
	}
}

// Connect запускает подключение в фоне и сразу возвращается.
func (m *Manager) Connect() {
	m.maintenance.Lock()
	defer m.maintenance.Unlock()
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	settings := m.settings
	m.state = m.idleState()
	m.state.Status = StatusConnecting
	state := m.state
	done := m.done
	m.mu.Unlock()
	m.notify(state)
	go m.run(ctx, settings, done)
}

// WhileIdle не даёт начать подключение посреди замены exe и запуска перезапуска.
// Длительные сетевые загрузки должны выполняться до входа в эту секцию.
func (m *Manager) WhileIdle(fn func()) bool {
	m.maintenance.Lock()
	defer m.maintenance.Unlock()
	if m.Active() {
		return false
	}
	fn()
	return true
}

// Disconnect останавливает sing-box и ждёт, пока он уберёт маршруты.
func (m *Manager) Disconnect() {
	m.DisconnectWithReason("команда приложения")
}

// DisconnectWithReason сохраняет источник остановки, не записывая настройки и секреты.
func (m *Manager) DisconnectWithReason(reason string) {
	m.mu.Lock()
	cancel, done := m.cancel, m.done
	m.mu.Unlock()
	if cancel == nil {
		return
	}
	m.log.Printf("запрошено отключение: %s", reason)
	cancel()
	<-done
}

func (m *Manager) run(ctx context.Context, settings Settings, done chan struct{}) {
	defer close(done)
	err := m.session(ctx, settings)
	// Ограниченные повторы только после аварийного завершения процесса.
	// Ошибки профиля и авторизации нельзя лечить бесконечными переподключениями.
	for attempt := 1; attempt <= 3 && ctx.Err() == nil && errors.Is(err, errProcessExited); attempt++ {
		m.Logf("sing-box завершился; повтор подключения %d из 3 через 5 секунд", attempt)
		m.update(func(s *State) { s.Status = StatusConnecting })
		sleep(ctx, 5*time.Second)
		if ctx.Err() != nil {
			break
		}
		err = m.session(ctx, settings)
	}

	m.mu.Lock()
	m.cancel = nil
	m.api = nil
	m.state = m.idleState()
	if err != nil && ctx.Err() == nil {
		m.state.Status = StatusError
		m.state.Error = err.Error()
		m.log.Printf("ошибка: %v", err)
	} else {
		m.log.Printf("отключено")
	}
	state := m.state
	m.mu.Unlock()
	m.notify(state)
}

func (m *Manager) session(ctx context.Context, settings Settings) error {
	m.log.Printf("подключение")
	m.update(func(s *State) {
		s.Corp.Up = false
		s.Corp.Detail = "подключение…"
		s.Error = ""
	})
	m.healthWarning("OpenVPN:", false, "")
	prof, err := settings.profile(m.paths)
	if err != nil {
		return err
	}
	in, err := singbox.FromProfile(ctx, prof, m.paths.Data)
	if err != nil {
		return err
	}
	for _, w := range in.Warnings() {
		m.log.Printf("предупреждение: %s", w)
	}
	addr, err := freeLocalAddr()
	if err != nil {
		return err
	}
	in.API = &singbox.API{Addr: addr, Secret: randomHex(16)}
	in.Inbound = m.inbound
	config, err := singbox.Build(in)
	if err != nil {
		return err
	}

	exe, release, err := m.singBox()
	if err != nil {
		return err
	}
	defer release()

	api := newClash(in.API.Addr, in.API.Secret)
	m.update(func(s *State) {
		s.Warnings = in.Warnings()
		s.Proxy = proxyStateFromInput(in, settings)
	})

	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	exited := make(chan struct{})
	var runErr error
	go func() {
		defer close(exited)
		runErr = runner.Run(runCtx, runner.Options{Exe: exe, Config: config, DataDir: m.paths.Data, Output: &sessionOutput{m: m}})
	}()

	if err := api.waitReady(ctx, 20*time.Second, exited); err != nil {
		stopRun()
		<-exited
		if ctx.Err() != nil {
			return nil
		}
		if runErr != nil {
			return fmt.Errorf("%w%s", runErr, m.log.tailHint())
		}
		return fmt.Errorf("%w%s", err, m.log.tailHint())
	}

	m.mu.Lock()
	m.api = api
	m.mu.Unlock()
	m.update(func(s *State) {
		s.Status = StatusConnected
		s.ConnectedAt = time.Now()
	})
	m.log.Printf("подключено")

	monitorCtx, stopMonitor := context.WithCancel(ctx)
	monitored := make(chan struct{})
	go func() {
		defer close(monitored)
		m.monitor(monitorCtx, api, in)
	}()
	defer func() {
		stopMonitor()
		<-monitored
	}()

	select {
	case <-ctx.Done():
		stopRun()
		<-exited
		return nil
	case <-exited:
		if runErr == nil {
			runErr = errors.New("sing-box неожиданно завершился")
		}
		return fmt.Errorf("%w: %v%s", errProcessExited, runErr, m.log.tailHint())
	}
}

var errProcessExited = errors.New("процесс sing-box неожиданно завершился")

func (m *Manager) singBox() (string, func(), error) {
	if m.singBoxPath != "" {
		return m.singBoxPath, func() {}, nil
	}
	data := singboxbin.Data()
	if data == nil {
		return "", nil, errors.New("в эту сборку не встроен sing-box; используйте релизную сборку или задайте VPNCLIENT_SINGBOX")
	}
	return runner.Install(m.paths.Data, data)
}

// monitor обновляет скорость, пинг и состояние OpenVPN, пока VPN подключён.
func (m *Manager) monitor(ctx context.Context, api *clash, in *singbox.Input) {
	var workers sync.WaitGroup
	defer workers.Wait()
	workers.Add(1)
	go func() {
		defer workers.Done()
		for ctx.Err() == nil {
			_ = api.traffic(ctx, func(t traffic) {
				m.update(func(s *State) { s.Up, s.Down = t.Up, t.Down })
			})
			sleep(ctx, time.Second)
		}
	}()

	multi := len(in.Servers) > 1
	if len(in.Servers) > 0 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for ctx.Err() == nil {
				reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				if multi {
					_ = api.groupDelay(reqCtx, singbox.TagAuto)
				}
				cancel()
				probeCtx, probeCancel := context.WithTimeout(ctx, 8*time.Second)
				_, err := api.delay(probeCtx, singbox.TagProxy)
				probeCancel()
				if ctx.Err() != nil {
					return
				}
				m.healthWarning("Прокси:", err != nil, "Прокси: проверка доступа не прошла; VPN запущен, но зарубежные сайты могут быть недоступны")
				dnsCtx, dnsCancel := context.WithTimeout(ctx, 8*time.Second)
				dnsErr := api.dnsQuery(dnsCtx, "www.youtube.com")
				dnsCancel()
				if ctx.Err() != nil {
					return
				}
				m.healthWarning("DNS:", dnsErr != nil, "DNS: проверка разрешения внешних имён не прошла; сайты могут не открываться")
				m.refreshProxies(ctx, api)
				sleep(ctx, 60*time.Second)
			}
		}()
	}

	if in.OpenVPN != nil {
		domains := in.Profile.Corporate.Domains
		for ctx.Err() == nil {
			up, detail := false, "подключение…"
			if len(domains) == 0 {
				up, detail = false, "нет домена для проверки доступа"
			} else {
				reqCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
				// Случайный поддомен не попадает в кэш DNS: ответ (даже NXDOMAIN)
				// означает, что корпоративный DNS доступен через туннель.
				err := api.dnsQuery(reqCtx, "vpnclient-probe-"+randomHex(4)+"."+domains[0])
				cancel()
				if err == nil {
					up, detail = true, "работает"
				} else if !strings.Contains(err.Error(), "not ready") {
					detail = shortError(err)
				}
			}
			m.update(func(s *State) {
				// Успешный ответ DNS API не отменяет явный отказ OpenVPN.
				if s.Corp.Detail != corpAuthFailed {
					s.Corp.Up, s.Corp.Detail = up, detail
				}
			})
			wait := 5 * time.Second
			if up {
				wait = 20 * time.Second
			}
			sleep(ctx, wait)
		}
	}
}

func (m *Manager) refreshProxies(ctx context.Context, api *clash) {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	proxies, err := api.proxies(reqCtx)
	if err != nil {
		return
	}
	m.update(func(s *State) {
		sel := proxies[singbox.TagProxy]
		if sel.Type == "Selector" || len(sel.All) > 0 {
			s.Proxy.Selected = sel.Now
			current := sel.Now
			if current == singbox.TagAuto {
				current = proxies[singbox.TagAuto].Now
			}
			s.Proxy.Current = current
			s.Proxy.Delay = proxies[current].delay()
			for i := range s.Proxy.Servers {
				s.Proxy.Servers[i].Delay = proxies[s.Proxy.Servers[i].Name].delay()
			}
		} else {
			s.Proxy.Delay = sel.delay()
			if len(s.Proxy.Servers) == 1 {
				s.Proxy.Servers[0].Delay = s.Proxy.Delay
			}
		}
	})
}

// SelectServer переключает сервер на лету; "auto" — самый быстрый.
func (m *Manager) SelectServer(name string) error {
	m.mu.Lock()
	m.settings.Server = name
	if name == singbox.TagAuto {
		m.settings.Server = ""
	}
	settings := m.settings
	api := m.api
	m.mu.Unlock()
	if err := saveSettings(m.paths, settings); err != nil {
		return err
	}
	m.update(func(s *State) { s.Proxy.Selected = name })
	if api == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := api.selectProxy(ctx, singbox.TagProxy, name); err != nil {
		return err
	}
	m.refreshProxies(ctx, api)
	return nil
}

// TestServers заново замеряет задержку до всех серверов.
func (m *Manager) TestServers() {
	m.mu.Lock()
	api := m.api
	multi := len(m.state.Proxy.Servers) > 1
	m.mu.Unlock()
	if api == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if multi {
		_ = api.groupDelay(ctx, singbox.TagAuto)
	} else {
		_, _ = api.delay(ctx, singbox.TagProxy)
	}
	m.refreshProxies(ctx, api)
}

func (m *Manager) LogFile() string { return m.paths.LogFile() }

// Log возвращает конец журнала (не больше max байт).
func (m *Manager) Log(max int64) ([]byte, error) {
	return m.log.tailBytes(max)
}

// Logf пишет сообщение в журнал приложения.
func (m *Manager) Logf(format string, a ...any) { m.log.Printf(format, a...) }

func (m *Manager) update(fn func(*State)) {
	m.mu.Lock()
	fn(&m.state)
	state := m.state
	m.mu.Unlock()
	m.notify(state)
}

func (m *Manager) notify(s State) {
	if m.onChange != nil {
		m.onChange(s)
	}
}

// idleState — состояние «отключено» с тем, что известно из настроек.
func (m *Manager) idleState() State {
	s := State{Status: StatusDisconnected}
	info := ovpnInfo(m.paths)
	s.Corp.Enabled = info.Loaded
	s.Corp.Domains = strings.Join(m.settings.CorpDomains, ", ")
	if info.Loaded {
		s.Corp.Detail = s.Corp.Domains
	}
	s.Proxy.Enabled = m.settings.Link != ""
	s.Proxy.Selected = m.settings.Server
	if s.Proxy.Selected == "" {
		s.Proxy.Selected = singbox.TagAuto
	}
	return s
}

func proxyStateFromInput(in *singbox.Input, settings Settings) ProxyState {
	p := ProxyState{Enabled: len(in.Servers) > 0, Selected: singbox.TagAuto}
	if settings.Server != "" {
		p.Selected = settings.Server
	}
	for _, l := range in.Servers {
		p.Servers = append(p.Servers, Server{Name: l.Name})
	}
	if len(in.Servers) == 1 {
		p.Current = in.Servers[0].Name
		p.Selected = p.Current
	}
	if sub := in.Subscription; sub != nil {
		p.Title = sub.Title
		p.Used = sub.Upload + sub.Download
		p.Total = sub.Total
		p.Expire = sub.Expire
		p.Updated = sub.FetchedAt
		p.Outdated = sub.FromCache
	}
	return p
}

func freeLocalAddr() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func shortError(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i < 80 {
		s = s[i+2:]
	}
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}
