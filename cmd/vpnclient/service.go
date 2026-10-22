//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/maks-ard/vpn-client/internal/app"
	"github.com/maks-ard/vpn-client/internal/ipc"
	"github.com/maks-ard/vpn-client/internal/update"
	"github.com/maks-ard/vpn-client/internal/winsvc"
)

// Service — методы, которые вызывает фронтенд (Call.ByName("main.Service.X")),
// и трей. Само подключение держит служба, окно управляет ей через ipc.
type Service struct {
	version string
	log     *slog.Logger
	client  *ipc.Client
	ctx     context.Context
	cancel  context.CancelFunc

	wapp   *application.App
	window application.Window

	tray       *application.SystemTray
	menu       *application.Menu
	statusItem *application.MenuItem
	toggleItem *application.MenuItem
	russiaItem *application.MenuItem

	mu        sync.Mutex
	state     app.State
	cached    app.Settings
	info      ipc.Info
	installCh chan struct{}

	trayMu      sync.Mutex
	lastIcon    string
	lastIconAt  time.Time
	lastTooltip string
	lastMenu    string

	quitting   atomic.Bool
	relaunched atomic.Bool
}

func newService(version string, logger *slog.Logger) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{
		version:   version,
		log:       logger,
		client:    ipc.NewClient(ipc.Dial),
		ctx:       ctx,
		cancel:    cancel,
		state:     app.State{Status: app.StatusDisconnected, Service: "unavailable"},
		cached:    app.Settings{CloseToTray: true, RussiaDirect: true},
		installCh: make(chan struct{}, 1),
	}
}

func (s *Service) init(wapp *application.App, window application.Window) {
	s.wapp, s.window = wapp, window
}

func (s *Service) call() (context.Context, context.CancelFunc) {
	return context.WithTimeout(s.ctx, 30*time.Second)
}

// ---------- методы для фронтенда ----------

// SettingsView — всё, что нужно экрану настроек.
type SettingsView struct {
	Settings app.Settings `json:"settings"`
	OVPN     app.OVPNInfo `json:"ovpn"`
	Version  string       `json:"version"`
}

func (s *Service) State() app.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Service) Settings() (SettingsView, error) {
	ctx, cancel := s.call()
	defer cancel()
	view, err := s.client.Settings(ctx)
	if err != nil {
		s.mu.Lock()
		cached := s.cached
		s.mu.Unlock()
		return SettingsView{Settings: cached, Version: s.versionLine()}, nil
	}
	info, infoErr := s.client.Info(ctx)
	s.mu.Lock()
	s.cached = view.Settings
	if infoErr == nil {
		s.info = info
	}
	s.mu.Unlock()
	return SettingsView{Settings: view.Settings, OVPN: view.OVPN, Version: s.versionLine()}, nil
}

func (s *Service) versionLine() string {
	s.mu.Lock()
	info := s.info
	s.mu.Unlock()
	v := "Версия " + s.version
	if info.SingBox != "" {
		v += " · sing-box " + info.SingBox
	}
	// Пока идёт загрузка или обновление готово, об этом говорит плашка ниже.
	if info.Update != "" && info.UpdateState == "" {
		v += " · " + info.Update
	}
	return v
}

func (s *Service) SaveSettings(settings app.Settings) error {
	prev := s.settings()
	ctx, cancel := s.call()
	defer cancel()
	if err := s.client.SaveSettings(ctx, settings); err != nil {
		return err
	}
	if settings.Autostart != prev.Autostart {
		if err := app.SetAutostart(settings.Autostart, s.guiExe()); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.cached = settings
	st := s.state
	s.mu.Unlock()
	s.refreshTray(st)
	return nil
}

func (s *Service) Toggle() error {
	// Служба не установлена или зависла — кнопка (пере)устанавливает её.
	if st := s.State(); st.Service == "missing" || (st.Service == "unavailable" && st.Error != "") {
		s.InstallService()
		return nil
	}
	ctx, cancel := s.call()
	defer cancel()
	return s.client.Toggle(ctx)
}

func (s *Service) SelectServer(name string) error {
	ctx, cancel := s.call()
	defer cancel()
	return s.client.SelectServer(ctx, name)
}

func (s *Service) TestServers() error {
	ctx, cancel := s.call()
	defer cancel()
	return s.client.TestServers(ctx)
}

func (s *Service) CheckUpdate() error {
	ctx, cancel := s.call()
	defer cancel()
	return s.client.CheckUpdate(ctx)
}

// UpdateView — загрузка обновления для индикатора и кнопки «Установить сейчас».
type UpdateView struct {
	State    string `json:"state"`
	Version  string `json:"version"`
	Progress int    `json:"progress"`
}

func updateView(info ipc.Info) UpdateView {
	return UpdateView{State: info.UpdateState, Version: info.UpdateVersion, Progress: info.UpdateProgress}
}

func (s *Service) Update() UpdateView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return updateView(s.info)
}

// InstallUpdate отключает VPN, ставит загруженное обновление и перезапускает
// службу; окно перезапустится из новой версии само (см. supervise).
func (s *Service) InstallUpdate() error {
	ctx, cancel := s.call()
	defer cancel()
	return s.client.InstallUpdate(ctx)
}

// watchUpdate опрашивает службу: загрузка идёт в фоне по расписанию,
// а событий о ней служба не рассылает.
func (s *Service) watchUpdate() {
	var last UpdateView
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
		info, err := s.client.Info(ctx)
		cancel()
		if err != nil {
			continue
		}
		s.mu.Lock()
		s.info = info
		s.mu.Unlock()
		if view := updateView(info); view != last {
			last = view
			s.wapp.Event.Emit("update", view)
		}
	}
}

// ChooseOVPN открывает диалог выбора файла. Возвращает nil, если
// пользователь передумал.
func (s *Service) ChooseOVPN() (*app.OVPNInfo, error) {
	path, err := s.wapp.Dialog.OpenFile().
		SetTitle("Файл конфигурации OpenVPN").
		AddFilter("Конфигурация OpenVPN (*.ovpn, *.conf)", "*.ovpn;*.conf").
		AttachToWindow(s.window).
		PromptForSingleSelection()
	if err != nil || path == "" {
		return nil, err
	}
	return s.LoadOVPN(path)
}

// LoadOVPN читает файл с правами пользователя, как и диалог выбора.
// Службе передаётся содержимое, а не путь к произвольному файлу SYSTEM.
func (s *Service) LoadOVPN(path string) (*app.OVPNInfo, error) {
	path = strings.Trim(strings.TrimSpace(path), "\"")
	if path == "" {
		return nil, errors.New("укажите путь к файлу .ovpn или .conf")
	}
	name, data, err := app.PrepareOVPN(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить .ovpn: %w", err)
	}
	ctx, cancel := s.call()
	defer cancel()
	info, err := s.client.ImportOVPN(ctx, name, data)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить .ovpn: %w", err)
	}
	return &info, nil
}

func (s *Service) RemoveOVPN() error {
	ctx, cancel := s.call()
	defer cancel()
	return s.client.RemoveOVPN(ctx)
}

// InstallService запускает установку службы (по кнопке в окне).
func (s *Service) InstallService() {
	select {
	case s.installCh <- struct{}{}:
	default:
	}
}

// CloseWindow — крестик в заголовке окна.
func (s *Service) CloseWindow() {
	if s.settings().CloseToTray {
		s.window.Hide()
		return
	}
	s.wapp.Quit()
}

func (s *Service) ShowWindow() {
	s.window.Show()
	s.window.UnMinimise()
	s.window.Focus()
}

// Quit — явный «Выход» в трее отключает VPN перед завершением окна.
func (s *Service) Quit() {
	go func() {
		s.log.Info("выход из трея: отключение VPN")
		ctx, cancel := s.call()
		defer cancel()
		if err := s.client.Disconnect(ctx); err != nil {
			s.log.Error("не удалось отключить VPN при выходе", "err", err)
			s.ShowWindow()
			return
		}
		s.quitting.Store(true)
		s.wapp.Quit()
	}()
}

func (s *Service) shutdown() {
	s.quitting.Store(true)
	// Жизненный цикл окна не должен управлять соединением службы:
	// обновление, выход из Windows и закрытие второго окна не равны «Отключить».
	s.cancel()
}

// OpenLog собирает журнал службы и окна в один файл и открывает его.
// Журнал службы читается напрямую из файла, если служба не отвечает.
func (s *Service) OpenLog() {
	ctx, cancel := s.call()
	defer cancel()
	var b strings.Builder
	data, err := s.client.Log(ctx)
	if err != nil {
		fmt.Fprintf(&b, "Служба не отвечает: %v\n\n", err)
		data, err = tailFile(filepath.Join(winsvc.LogDir(), "vpnclient.log"), 512<<10)
		if err != nil {
			fmt.Fprintf(&b, "Журнал службы недоступен: %v\n", err)
		}
	}
	b.WriteString("===== Журнал службы =====\n")
	b.Write(data)
	gui, _ := tailFile(filepath.Join(guiDir(), "gui.log"), 128<<10)
	b.WriteString("\n===== Журнал окна =====\n")
	b.Write(gui)
	data = []byte(b.String())
	path := filepath.Join(os.TempDir(), "vpn-client-log.txt")
	if err := os.WriteFile(path, data, 0o600); err == nil {
		_ = app.OpenFile(path)
	}
}

func (s *Service) settings() app.Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cached
}

// guiExe — какой exe ставить в автозапуск: установленный, если он есть.
func (s *Service) guiExe() string {
	if _, err := os.Stat(winsvc.InstalledExe()); err == nil {
		return winsvc.InstalledExe()
	}
	exe, _ := os.Executable()
	return exe
}

// ---------- связь со службой ----------

func (s *Service) setState(st app.State) {
	s.mu.Lock()
	s.state = st
	s.mu.Unlock()
	if s.wapp != nil {
		s.wapp.Event.Emit("state", st)
	}
	s.refreshTray(st)
}

func (s *Service) setServiceStatus(status, msg string) {
	if status != "" || msg != "" {
		s.log.Info("состояние службы", "status", status, "msg", msg)
	}
	st := app.State{Status: app.StatusDisconnected, Service: status, Error: msg}
	if msg != "" {
		st.Status = app.StatusError
	}
	s.setState(st)
}

// supervise держит связь со службой: ставит её при первом запуске,
// перезапускает окно после обновления и переподключается, если служба
// перезапускалась.
func (s *Service) supervise() {
	triedInstall := false
	relaunchFailed := false
	firstConnect := true
	var unavailableSince time.Time
	for s.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
		info, err := s.client.Info(ctx)
		cancel()

		if err != nil {
			installed, running := winsvc.ServiceRunning()
			if !installed {
				// Первый раз ставим сами, дальше — по кнопке в окне.
				if triedInstall {
					if s.State().Service != "missing" {
						s.setServiceStatus("missing", "")
					}
					s.waitInstallRequest()
				}
				triedInstall = true
				s.install()
				continue
			}
			if unavailableSince.IsZero() {
				unavailableSince = time.Now()
			}
			msg := ""
			waited := time.Since(unavailableSince)
			switch {
			case !running && waited > 5*time.Second:
				msg = "Служба остановлена. Нажмите кнопку, чтобы запустить её (понадобятся права администратора)."
			case waited > 20*time.Second:
				msg = "Служба запущена, но не отвечает. Нажмите кнопку, чтобы перезапустить её (понадобятся права администратора)."
			}
			if msg != "" {
				if _, statErr := os.Stat(winsvc.InstalledExe()); statErr != nil {
					// Служба зарегистрирована, а её exe нет — его удалил антивирус.
					msg = winsvc.AntivirusHint
				}
				s.log.Error("служба недоступна", "running", running, "err", err)
			}
			s.setServiceStatus("unavailable", msg)
			select {
			case <-s.ctx.Done():
				return
			case <-s.installCh:
				unavailableSince = time.Time{}
				s.install()
			case <-time.After(2 * time.Second):
			}
			continue
		}
		unavailableSince = time.Time{}

		s.mu.Lock()
		s.info = info
		s.mu.Unlock()
		s.log.Info("служба на связи", "версия", info.Version, "exe", info.Exe)

		switch {
		case update.Newer(s.version, info.Version) && !triedInstall:
			// Окно новее службы (скачали новую версию вручную) — обновляем службу.
			triedInstall = true
			s.install()
			continue
		case update.Newer(info.Version, s.version) && !relaunchFailed:
			// Служба обновилась сама — перезапускаем окно из новой версии.
			if s.relaunch(info.Exe) {
				return
			}
			// Не вышло — продолжаем работать со службой из этого окна,
			// новая версия окна откроется при следующем запуске.
			relaunchFailed = true
		}

		if firstConnect {
			firstConnect = false
			s.migrateOldSettings()
			s.afterConnect()
		}

		err = s.client.Events(s.ctx, s.setState)
		if s.ctx.Err() != nil {
			return
		}
		_ = err
		s.setServiceStatus("unavailable", "")
		sleep(s.ctx, time.Second)
	}
}

// afterConnect — однократные действия при первом подключении к службе.
func (s *Service) afterConnect() {
	view, err := s.Settings()
	if err != nil {
		return
	}
	if view.Settings.Autostart {
		// Путь мог поменяться (установка в Program Files).
		_ = app.SetAutostart(true, s.guiExe())
	}
	if view.Settings.ConnectOnStart {
		ctx, cancel := s.call()
		st, err := s.client.State(ctx)
		if err == nil && st.Status == app.StatusDisconnected {
			_ = s.client.Toggle(ctx)
		}
		cancel()
	}
}

func (s *Service) waitInstallRequest() {
	select {
	case <-s.ctx.Done():
	case <-s.installCh:
	}
}

// install ставит или обновляет службу с запросом прав администратора.
func (s *Service) install() {
	s.setServiceStatus("installing", "")
	self, err := os.Executable()
	if err != nil {
		s.setServiceStatus("missing", err.Error())
		return
	}
	_ = os.Remove(installErrorFile())
	s.ShowWindow()
	s.log.Info("установка службы", "exe", self)
	code, err := winsvc.RunElevated(uintptr(s.window.NativeWindow()), self, "--install")
	s.log.Info("установка завершилась", "code", code, "err", err)
	switch {
	case errors.Is(err, winsvc.ErrCancelled):
		s.setServiceStatus("missing", "Без службы VPN работать не будет. Нажмите кнопку, чтобы установить её.")
		return
	case err != nil:
		s.setServiceStatus("missing", "Установка службы: "+err.Error())
		return
	case code != 0:
		msg := fmt.Sprintf("Установка службы не удалась (код %d)", code)
		if text, err := os.ReadFile(installErrorFile()); err == nil && len(text) > 0 {
			msg += ": " + strings.TrimSpace(string(text))
		}
		s.setServiceStatus("missing", msg)
		return
	}

	// Служба поставлена в Program Files — дальше работаем из установленной копии.
	if !samePath(self, winsvc.InstalledExe()) {
		s.waitService(15 * time.Second)
		if !s.relaunch(winsvc.InstalledExe()) {
			s.setServiceStatus("", "Служба установлена, но окно из C:\\Program Files\\vpn-client не запустилось — "+
				"вероятно, его блокирует антивирус. Откройте vpn-client из меню «Пуск».")
		}
	}
}

func (s *Service) waitService(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) && s.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(s.ctx, time.Second)
		_, err := s.client.Info(ctx)
		cancel()
		if err == nil {
			return
		}
		sleep(s.ctx, 300*time.Millisecond)
	}
}

// relaunch запускает другой exe окна и закрывает этот, не трогая VPN.
// Свежезаписанный exe антивирус может какое-то время не давать запустить
// («Access is denied»), поэтому пробуем около минуты. Возвращает false,
// если запустить так и не удалось — тогда окно продолжает работать как есть.
func (s *Service) relaunch(exe string) bool {
	if exe == "" {
		exe = winsvc.InstalledExe()
	}
	s.log.Info("перезапуск окна", "exe", exe)
	var err error
	for attempt := 0; attempt < 20 && s.ctx.Err() == nil; attempt++ {
		if attempt > 0 {
			sleep(s.ctx, 3*time.Second)
		}
		cmd := exec.Command(exe, "--wait-pid", strconv.Itoa(os.Getpid()))
		if !s.window.IsVisible() {
			cmd.Args = append(cmd.Args, "--autostart")
		}
		if err = cmd.Start(); err == nil {
			_ = cmd.Process.Release()
			s.relaunched.Store(true)
			s.Quit()
			return true
		}
		s.log.Warn("перезапуск окна не удался", "attempt", attempt+1, "err", err)
	}
	s.log.Error("окно не перезапущено", "err", err)
	return false
}

// migrateOldSettings переносит настройки версий 0.1.x, которые хранились
// в %APPDATA%\vpn-client, если у службы настроек ещё нет.
func (s *Service) migrateOldSettings() {
	old, err := app.DefaultPaths()
	if err != nil {
		return
	}
	marker := filepath.Join(old.Config, "migrated")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	data, err := os.ReadFile(filepath.Join(old.Config, "settings.json"))
	if err != nil {
		return
	}
	ctx, cancel := s.call()
	defer cancel()
	view, err := s.client.Settings(ctx)
	if err != nil || view.Settings.Link != "" || view.OVPN.Loaded {
		_ = os.WriteFile(marker, nil, 0o600)
		return
	}
	var settings app.Settings
	if json.Unmarshal(data, &settings) != nil {
		return
	}
	if err := s.client.SaveSettings(ctx, settings); err != nil {
		return
	}
	if ovpn, err := os.ReadFile(filepath.Join(old.Config, "corp.ovpn")); err == nil {
		name := "corp.ovpn"
		if n, err := os.ReadFile(filepath.Join(old.Config, "corp.ovpn.name")); err == nil {
			name = strings.TrimSpace(string(n))
		}
		_, _ = s.client.ImportOVPN(ctx, name, ovpn)
	}
	_ = os.WriteFile(marker, nil, 0o600)
	s.wapp.Event.Emit("settings-changed")
}

// ---------- трей ----------

func (s *Service) setupTray() {
	s.menu = s.wapp.NewMenu()
	s.statusItem = s.menu.Add("Отключено").SetEnabled(false)
	s.menu.AddSeparator()
	s.toggleItem = s.menu.Add("Подключить").OnClick(func(*application.Context) { go s.Toggle() })
	s.menu.Add("Открыть окно").OnClick(func(*application.Context) { s.ShowWindow() })
	s.menu.AddSeparator()
	s.russiaItem = s.menu.AddCheckbox("Российские сайты напрямую", true).
		OnClick(func(ctx *application.Context) {
			settings := s.settings()
			settings.RussiaDirect = ctx.ClickedMenuItem().Checked()
			go func() {
				if err := s.SaveSettings(settings); err == nil {
					s.wapp.Event.Emit("settings-changed")
				}
			}()
		})
	s.menu.Add("Журнал").OnClick(func(*application.Context) { go s.OpenLog() })
	s.menu.AddSeparator()
	s.menu.Add("Выход").OnClick(func(*application.Context) { s.Quit() })

	s.tray = s.wapp.SystemTray.New()
	s.tray.SetIcon(icon("tray-disconnected"))
	s.tray.SetTooltip("vpn-client")
	s.tray.SetMenu(s.menu)
	s.tray.OnClick(s.ShowWindow)
	s.tray.OnDoubleClick(func() { go s.Toggle() })
	s.refreshTray(s.State())
}

func (s *Service) refreshTray(st app.State) {
	if s.tray == nil {
		return
	}
	s.trayMu.Lock()
	defer s.trayMu.Unlock()

	iconName := "tray-" + string(st.Status)
	status := map[app.Status]string{
		app.StatusDisconnected: "Отключено",
		app.StatusConnecting:   "Подключение…",
		app.StatusConnected:    "Подключено",
		app.StatusError:        "Ошибка подключения",
	}[st.Status]
	switch st.Service {
	case "missing":
		status, iconName = "Служба не установлена", "tray-error"
	case "installing":
		status, iconName = "Установка службы…", "tray-connecting"
	case "unavailable":
		status, iconName = "Служба недоступна", "tray-disconnected"
	}
	// Wails молча откатывает иконку, если Explorer ещё не зарегистрировал её
	// (старт системы, перезапуск Explorer), поэтому периодически ставим заново.
	if iconName != s.lastIcon || time.Since(s.lastIconAt) > 10*time.Second {
		s.tray.SetIcon(icon(iconName))
		s.lastIcon, s.lastIconAt = iconName, time.Now()
	}

	var parts []string
	if st.Status == app.StatusConnected {
		if st.Corp.Enabled {
			parts = append(parts, "OpenVPN "+map[bool]string{true: "доступен", false: "доступ не подтверждён"}[st.Corp.Up])
		}
		if st.Proxy.Enabled && st.Proxy.Current != "" {
			available := false
			for _, check := range st.Proxy.Checks {
				available = available || check.OK
			}
			parts = append(parts, "VLESS: "+map[bool]string{true: "есть доступ", false: "доступ не подтверждён"}[available])
		}
	}
	tooltip := "vpn-client — " + strings.ToLower(status[:1]) + status[1:]
	if len(parts) > 0 {
		tooltip += "\n" + strings.Join(parts, ", ")
	}
	if st.Status == app.StatusError && st.Error != "" {
		tooltip += "\n" + truncate(st.Error, 100)
	}
	// Состояние приходит раз в секунду (скорость), а трей и меню трогаем
	// только при реальных изменениях.
	if tooltip = truncate(tooltip, 127); tooltip != s.lastTooltip {
		s.tray.SetTooltip(tooltip)
		s.lastTooltip = tooltip
	}

	toggle := "Подключить"
	if st.Status == app.StatusConnecting || st.Status == app.StatusConnected {
		toggle = "Отключить"
	}
	if st.Service == "missing" {
		toggle = "Установить службу"
	}
	russia := s.settings().RussiaDirect
	if key := fmt.Sprint(status, toggle, russia); key != s.lastMenu {
		s.statusItem.SetLabel(status)
		s.toggleItem.SetLabel(toggle)
		s.russiaItem.SetChecked(russia)
		s.menu.Update()
		s.lastMenu = key
	}
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func samePath(a, b string) bool {
	a, _ = filepath.Abs(a)
	b, _ = filepath.Abs(b)
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func tailFile(path string, max int64) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		data = data[int64(len(data))-max:]
	}
	return data, nil
}
