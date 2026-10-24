package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maks-ard/vpn-client/internal/profile"
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
	Current string         `json:"current"`
	Delay   int            `json:"delay"` // мс, 0 — неизвестно
	Servers []Server       `json:"servers"`
	Checks  []ServiceCheck `json:"checks,omitempty"`

	Title         string    `json:"title,omitempty"`
	Used          int64     `json:"used,omitempty"`
	Total         int64     `json:"total,omitempty"`
	Expire        time.Time `json:"expire,omitempty"`
	Updated       time.Time `json:"updated,omitempty"`
	Outdated      bool      `json:"outdated,omitempty"`
	MetadataError bool      `json:"metadataError,omitempty"`
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

	mu             sync.Mutex
	maintenance    sync.Mutex
	updating       bool
	settingsMu     sync.Mutex
	subscriptionMu sync.Mutex
	nextConnect    time.Time
	// corpRetries — перезапуски подряд после завершения OpenVPN, пока он ни разу не поднялся.
	corpRetries int
	settings    Settings
	state       State
	cancel      context.CancelFunc
	done        chan struct{}
	api         *clash
	// handedOff — sing-box отдан новой версии службы: новое подключение
	// создало бы второй TUN рядом с работающим.
	handedOff bool
	handoffCh chan chan handoffReply
}

func NewManager(paths Paths, onChange func(State)) (*Manager, error) {
	s, err := loadSettings(paths)
	log := newLogFile(paths.LogFile())
	if err != nil {
		log.Printf("%v", err)
	}
	log.redact(s.Link)
	m := &Manager{paths: paths, onChange: onChange, log: log, settings: s, singBoxPath: os.Getenv("VPNCLIENT_SINGBOX"),
		handoffCh: make(chan chan handoffReply)}
	m.state = m.idleState()
	m.loadSubscriptionInfo()
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
	// Быстрые добавления доменов не должны запускать пересекающиеся
	// циклы остановки и повторного входа на корпоративный сервер.
	m.settingsMu.Lock()
	defer m.settingsMu.Unlock()
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
		previous := m.state.Proxy
		m.state = m.idleState()
		if old.Link == s.Link {
			m.state.Proxy = previous
		}
	}
	if old.Link != s.Link {
		m.state.Proxy.Expire = time.Time{}
		m.state.Proxy.Updated = time.Time{}
		m.state.Proxy.Title = ""
		m.state.Proxy.Used, m.state.Proxy.Total = 0, 0
		m.state.Proxy.Outdated, m.state.Proxy.MetadataError = false, false
	}
	state := m.state
	m.mu.Unlock()
	m.notify(state)

	if old.Link != s.Link {
		go m.RefreshSubscription(context.Background())
	}
	if active && routingChanged(old, s) {
		m.log.Printf("настройки изменены, переподключение")
		m.DisconnectWithReason("изменение настроек маршрутизации")
		m.Connect()
	}
	return nil
}

func routingChanged(a, b Settings) bool {
	return a.Link != b.Link || a.OVPNUsername != b.OVPNUsername || a.OVPNPassword != b.OVPNPassword ||
		a.RussiaDirect != b.RussiaDirect || strings.Join(a.CorpDomains, ",") != strings.Join(b.CorpDomains, ",") ||
		effectiveCategories(a.Categories) != effectiveCategories(b.Categories)
}

// effectiveCategories сводит категории к тому, что реально попадает в конфиг:
// категории с направлением «auto» ничего не меняют, поэтому переключение
// между «нет категории» и «auto» не должно вызывать переподключение.
func effectiveCategories(cats []profile.Category) string {
	var active []profile.Category
	for _, c := range cats {
		if c.Action != profile.ActionAuto {
			c.Name = "" // название на конфиг не влияет
			active = append(active, c)
		}
	}
	data, _ := json.Marshal(active)
	return string(data)
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
	return cloneState(m.state)
}

// Снимки передаются HTTP и окну после снятия блокировки: срезы не должны
// разделять память с обновляемым состоянием менеджера.
func cloneState(s State) State {
	s.Warnings = append([]string(nil), s.Warnings...)
	s.Proxy.Servers = append([]Server(nil), s.Proxy.Servers...)
	s.Proxy.Checks = append([]ServiceCheck(nil), s.Proxy.Checks...)
	return s
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
	if m.updating {
		return
	}
	m.mu.Lock()
	if m.cancel != nil || m.handedOff {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	m.corpRetries = 0
	settings := m.settings
	metadata := m.state.Proxy
	m.state = m.idleState()
	m.state.Proxy.Title, m.state.Proxy.Used, m.state.Proxy.Total = metadata.Title, metadata.Used, metadata.Total
	m.state.Proxy.Expire, m.state.Proxy.Updated = metadata.Expire, metadata.Updated
	m.state.Proxy.Outdated, m.state.Proxy.MetadataError = metadata.Outdated, metadata.MetadataError
	m.state.Status = StatusConnecting
	state := m.state
	done := m.done
	m.mu.Unlock()
	m.notify(state)
	go m.run(ctx, settings, done, nil)
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

// InstallWhileIdle резервирует простой до завершения перезапуска службы.
// После успешного запуска обновления новое подключение не должно обогнать SCM.
func (m *Manager) InstallWhileIdle(fn func() error) (bool, error) {
	m.maintenance.Lock()
	defer m.maintenance.Unlock()
	if m.Active() || m.updating {
		return false, nil
	}
	if err := fn(); err != nil {
		return true, err
	}
	m.updating = true
	return true, nil
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

// run ведёт подключение до отключения; adopted — sing-box, подхваченный
// у прошлой версии службы, вместо запуска своего.
func (m *Manager) run(ctx context.Context, settings Settings, done chan struct{}, adopted *liveSession) {
	defer close(done)
	var err error
	if adopted != nil {
		err = m.supervise(ctx, adopted)
		adopted.release()
	} else {
		err = m.session(ctx, settings)
	}
	// Повторяем, только если связь уже была установлена и оборвалась.
	// Ошибки профиля и запуска так не лечатся и сразу показываются пользователю.
	for attempt := 1; ctx.Err() == nil && (errors.Is(err, errProcessExited) || errors.Is(err, errCorpTerminated)); attempt++ {
		reason := "sing-box завершился"
		if errors.Is(err, errCorpTerminated) {
			reason = err.Error()
		}
		m.Logf("%s; повторное подключение через %s (попытка %d)", reason, reconnectDelay, attempt)
		m.update(func(s *State) { s.Status = StatusConnecting })
		sleep(ctx, reconnectDelay)
		if ctx.Err() != nil {
			break
		}
		err = m.session(ctx, settings)
	}

	if errors.Is(err, errHandedOff) {
		// Состояние не сбрасываем: VPN продолжает работать в новой версии службы.
		m.mu.Lock()
		m.cancel = nil
		m.api = nil
		m.mu.Unlock()
		m.log.Printf("sing-box передан новой версии службы")
		return
	}

	m.mu.Lock()
	m.cancel = nil
	m.nextConnect = time.Now().Add(5 * time.Second)
	m.api = nil
	proxy := m.state.Proxy
	m.state = m.idleState()
	// Срок и лимиты подписки остаются полезны после отключения туннеля.
	m.state.Proxy.Title = proxy.Title
	m.state.Proxy.Expire = proxy.Expire
	m.state.Proxy.Updated = proxy.Updated
	m.state.Proxy.Used = proxy.Used
	m.state.Proxy.Total = proxy.Total
	m.state.Proxy.Outdated = proxy.Outdated
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
	m.mu.Lock()
	wait := time.Until(m.nextConnect)
	m.mu.Unlock()
	if wait > 0 {
		m.Logf("пауза перед повторным подключением: ожидание закрытия предыдущей сессии")
		sleep(ctx, wait)
		if ctx.Err() != nil {
			return nil
		}
	}
	m.log.Printf("подключение")
	m.update(func(s *State) {
		s.Corp.Up = false
		s.Corp.Detail = corpConnecting
		s.Proxy.Checks = nil
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

	output := newSessionOutput(m)
	proc, err := runner.Start(runner.Options{Exe: exe, Config: config, DataDir: m.paths.Data, Output: output})
	if err != nil {
		return err
	}
	if err := api.waitReady(ctx, 20*time.Second, proc.Done()); err != nil {
		exited := false
		select {
		case <-proc.Done():
			exited = true
		default:
		}
		proc.Stop()
		if ctx.Err() != nil {
			return nil
		}
		if exited {
			return fmt.Errorf("%w%s", proc.Err(), m.log.tailHint())
		}
		return fmt.Errorf("%w%s", err, m.log.tailHint())
	}
	return m.supervise(ctx, &liveSession{proc: proc, api: api, output: output, info: sessionInfo{
		APIAddr: in.API.Addr, APISecret: in.API.Secret, Servers: len(in.Servers), Corp: in.OpenVPN != nil,
		CorpDomains: in.Profile.Corporate.Domains, LogLevel: in.Profile.SingBox.LogLevel,
	}})
}

// sessionInfo — что нужно для наблюдения за работающим sing-box; передаётся
// новой версии службы вместе с процессом.
type sessionInfo struct {
	APIAddr     string   `json:"apiAddr"`
	APISecret   string   `json:"apiSecret"`
	Servers     int      `json:"servers"`
	Corp        bool     `json:"corp"`
	CorpDomains []string `json:"corpDomains,omitempty"`
	LogLevel    string   `json:"logLevel"`
}

// liveSession — sing-box, который уже поднял API.
type liveSession struct {
	proc    *runner.Process
	api     *clash
	output  *sessionOutput
	info    sessionInfo
	adopted bool
	// unlock отпускает файл sing-box подхваченного процесса.
	unlock func()
}

func (s *liveSession) release() {
	if s.unlock != nil {
		s.unlock()
	}
}

// supervise следит за работающим sing-box, пока его не остановят, он не
// завершится сам или не будет передан новой версии службы.
func (m *Manager) supervise(ctx context.Context, live *liveSession) error {
	m.mu.Lock()
	m.api = live.api
	m.mu.Unlock()
	if !live.adopted {
		m.update(func(s *State) {
			s.Status = StatusConnected
			s.ConnectedAt = time.Now()
		})
		m.log.Printf("подключено")
	}

	monitorCtx, stopMonitor := context.WithCancel(ctx)
	var monitored sync.WaitGroup
	monitored.Add(1)
	go func() {
		defer monitored.Done()
		m.monitor(monitorCtx, live.api, live.info)
	}()
	if live.adopted {
		// stdout подхваченного процесса остался у прошлой версии службы.
		monitored.Add(1)
		go func() {
			defer monitored.Done()
			m.streamLogs(monitorCtx, live.api, live.info.LogLevel, live.output)
		}()
	}
	defer func() {
		stopMonitor()
		monitored.Wait()
	}()

	corpDown := live.output.corpDown
	for {
		select {
		case <-ctx.Done():
			live.proc.Stop()
			return nil
		case <-live.proc.Done():
			return fmt.Errorf("%w: %v%s", errProcessExited, live.proc.Err(), m.log.tailHint())
		case reply := <-m.handoffCh:
			h, err := live.proc.Handoff()
			if err != nil {
				reply <- handoffReply{err: err}
				continue
			}
			reply <- handoffReply{handoff: Handoff{Process: h, Session: live.info, State: m.State()}}
			return errHandedOff
		case <-corpDown:
			// sing-box не поднимает завершившийся endpoint OpenVPN сам, поэтому
			// перезапускаем сессию целиком; VLESS прерывается на несколько секунд.
			_, auth := live.output.corpTerminated()
			if !m.allowCorpRetry() {
				m.Logf("OpenVPN: %d перезапуска подряд не помогли, повторы остановлены до следующего подключения", maxCorpRetries)
				corpDown = nil
				continue
			}
			live.proc.Stop()
			if auth {
				return fmt.Errorf("%w: сервер отклонил авторизацию", errCorpTerminated)
			}
			return errCorpTerminated
		}
	}
}

var (
	errProcessExited  = errors.New("процесс sing-box неожиданно завершился")
	errCorpTerminated = errors.New("OpenVPN отключился")
	errHandedOff      = errors.New("sing-box передан новой версии службы")
)

const (
	reconnectDelay = 5 * time.Second
	// Сервер иногда отвечает AUTH_FAILED на верные данные, но бесконечные
	// повторы с неверным паролем заблокируют учётную запись, а ошибку
	// сертификата перезапуск не исправит и только будет рвать VLESS.
	maxCorpRetries = 3
)

func (m *Manager) allowCorpRetry() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.corpRetries >= maxCorpRetries {
		return false
	}
	m.corpRetries++
	return true
}

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
func (m *Manager) monitor(ctx context.Context, api *clash, info sessionInfo) {
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

	multi := info.Servers > 1
	if info.Servers > 0 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for ctx.Err() == nil {
				reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				if multi {
					_ = api.groupDelay(reqCtx, singbox.TagAuto)
				}
				cancel()
				ok := m.checkServices(ctx, api)
				if !ok && multi && m.failover(ctx, api) {
					ok = m.checkServices(ctx, api)
				}
				if ctx.Err() != nil {
					return
				}
				dnsCtx, dnsCancel := context.WithTimeout(ctx, 8*time.Second)
				dnsErr := api.dnsQuery(dnsCtx, "www.youtube.com")
				dnsCancel()
				if ctx.Err() != nil {
					return
				}
				m.healthWarning("DNS:", dnsErr != nil, "DNS: проверка разрешения внешних имён не прошла; сайты могут не открываться")
				m.refreshProxies(ctx, api)
				// Пока зарубежные сайты недоступны, проверяем и ищем рабочий сервер чаще.
				wait := 60 * time.Second
				if !ok {
					wait = reconnectDelay
				}
				sleep(ctx, wait)
			}
		}()
	}

	if info.Corp {
		domains := info.CorpDomains
		// Первые секунды туннель ещё поднимается: таймауты DNS — не ошибка.
		lastUp, everUp := time.Now(), false
		for ctx.Err() == nil {
			up, detail := false, corpConnecting
			if everUp {
				detail = corpReconnecting
			}
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
				} else if !strings.Contains(err.Error(), "not ready") && time.Since(lastUp) > corpGrace {
					detail = shortError(err)
				}
			}
			if up {
				lastUp, everUp = time.Now(), true
				m.mu.Lock()
				m.corpRetries = 0
				m.mu.Unlock()
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

const (
	corpConnecting   = "подключение…"
	corpReconnecting = "переподключение…"
	// corpGrace — сколько ждать подъёма OpenVPN до показа ошибки: столько
	// занимает рукопожатие и повторы sing-box после обрыва.
	corpGrace = 30 * time.Second
)

// failover в режиме «авто» закрепляет сервер, через который открывается больше
// всего сервисов. urltest меряет только YouTube и раз в 5 минут, поэтому после
// обрыва долго держится за сервер, который уже не работает.
func (m *Manager) failover(ctx context.Context, api *clash) bool {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	proxies, err := api.proxies(reqCtx)
	cancel()
	if err != nil || m.Settings().Server != "" {
		return false
	}
	selector := proxies[singbox.TagProxy]
	var servers []string
	for _, name := range selector.All {
		if name != singbox.TagAuto {
			servers = append(servers, name)
		}
	}
	best := bestServer(ctx, api, servers)
	if best == "" || ctx.Err() != nil {
		return false
	}
	// Пользователь мог выбрать сервер вручную, пока шла проверка.
	m.settingsMu.Lock()
	defer m.settingsMu.Unlock()
	if m.Settings().Server != "" || selector.Now == best {
		return false
	}
	reqCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := api.selectProxy(reqCtx, singbox.TagProxy, best); err != nil {
		m.Logf("VLESS: не удалось переключиться на %s: %v", best, err)
		return false
	}
	m.Logf("VLESS: проверочные сайты недоступны, выбран сервер %s", best)
	return true
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
		// Единственный сервер с несколькими вариантами — urltest под тегом
		// proxy: выбирать в нём нечего, показываем общую задержку.
		if sel.Type != "URLTest" && (sel.Type == "Selector" || len(sel.All) > 0) {
			s.Proxy.Selected = sel.Now
			// failover закрепляет сервер в selector, но выбор пользователя — «авто».
			if m.settings.Server == "" {
				s.Proxy.Selected = singbox.TagAuto
			}
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
	m.settingsMu.Lock()
	defer m.settingsMu.Unlock()
	m.mu.Lock()
	valid := name == singbox.TagAuto
	for _, server := range m.state.Proxy.Servers {
		valid = valid || server.Name == name
	}
	if !valid {
		m.mu.Unlock()
		return errors.New("сервер отсутствует в текущем списке")
	}
	settings := m.settings
	previousServer := m.state.Proxy.Selected
	settings.Server = name
	if name == singbox.TagAuto {
		settings.Server = ""
	}
	api := m.api
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if api != nil {
		if err := api.selectProxy(ctx, singbox.TagProxy, name); err != nil {
			return err
		}
	}
	if err := saveSettings(m.paths, settings); err != nil {
		if api != nil && previousServer != "" {
			return errors.Join(err, api.selectProxy(ctx, singbox.TagProxy, previousServer))
		}
		return err
	}
	m.mu.Lock()
	m.settings = settings
	m.mu.Unlock()
	m.update(func(s *State) { s.Proxy.Selected = name; s.Proxy.Checks = nil })
	if api != nil {
		m.refreshProxies(ctx, api)
	}
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
	m.checkServices(ctx, api)
}

func (m *Manager) LogFile() string { return m.paths.LogFile() }

// Close освобождает процесс VPN и журнал при завершении владельца менеджера.
func (m *Manager) Close() error {
	m.DisconnectWithReason("завершение менеджера")
	return m.log.Close()
}

// Log возвращает конец журнала (не больше max байт).
func (m *Manager) Log(max int64) ([]byte, error) {
	return m.log.tailBytes(max)
}

// Logf пишет сообщение в журнал приложения.
func (m *Manager) Logf(format string, a ...any) { m.log.Printf(format, a...) }

func (m *Manager) update(fn func(*State)) {
	m.mu.Lock()
	m.state = cloneState(m.state)
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
	for _, s := range in.Servers {
		p.Servers = append(p.Servers, Server{Name: s.Name})
		// Сохранённого сервера может уже не быть в подписке — тогда, как и
		// sing-box, остаёмся на «авто».
		if s.Name == settings.Server {
			p.Selected = s.Name
		}
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

// freeLocalAddr выбирает порт для Clash API ниже динамического диапазона
// Windows (49152+): из него Hyper-V и WinNAT резервируют порты в любой момент,
// и sing-box получал «bind: forbidden by its access permissions».
func freeLocalAddr() (string, error) {
	for range 50 {
		port := 20000 + mrand.IntN(29000)
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			addr := l.Addr().String()
			_ = l.Close()
			return addr, nil
		}
	}
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
