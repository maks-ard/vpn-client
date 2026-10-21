//go:build windows

package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/maks-ard/vpn-client/internal/app"
	"github.com/maks-ard/vpn-client/internal/singboxbin"
)

// Service — методы, которые вызывает фронтенд (Call.ByName("main.Service.X")),
// плюс трей. Вся логика — в internal/app.
type Service struct {
	wapp    *application.App
	window  application.Window
	manager *app.Manager
	version string

	tray       *application.SystemTray
	menu       *application.Menu
	statusItem *application.MenuItem
	toggleItem *application.MenuItem
	russiaItem *application.MenuItem

	trayMu     sync.Mutex
	lastStatus app.Status
	quitting   atomic.Bool
}

func (s *Service) init(wapp *application.App, window application.Window, m *app.Manager, version string) {
	s.wapp, s.window, s.manager, s.version = wapp, window, m, version
}

// SettingsView — всё, что нужно экрану настроек.
type SettingsView struct {
	Settings app.Settings `json:"settings"`
	OVPN     app.OVPNInfo `json:"ovpn"`
	Version  string       `json:"version"`
}

func (s *Service) State() app.State { return s.manager.State() }

func (s *Service) Settings() SettingsView {
	v := "Версия " + s.version
	if singboxbin.Version != "" {
		v += " · sing-box " + singboxbin.Version
	}
	return SettingsView{Settings: s.manager.Settings(), OVPN: s.manager.OVPN(), Version: v}
}

func (s *Service) SaveSettings(settings app.Settings) error {
	if err := s.manager.SaveSettings(settings); err != nil {
		return err
	}
	s.refreshTray(s.manager.State())
	return nil
}

func (s *Service) Toggle() { go s.manager.Toggle() }

func (s *Service) SelectServer(name string) error { return s.manager.SelectServer(name) }

func (s *Service) TestServers() { s.manager.TestServers() }

// ChooseOVPN открывает диалог выбора файла. Возвращает nil, если пользователь
// передумал.
func (s *Service) ChooseOVPN() (*app.OVPNInfo, error) {
	path, err := s.wapp.Dialog.OpenFile().
		SetTitle("Файл конфигурации OpenVPN").
		AddFilter("Конфигурация OpenVPN (*.ovpn, *.conf)", "*.ovpn;*.conf").
		AttachToWindow(s.window).
		PromptForSingleSelection()
	if err != nil || path == "" {
		return nil, err
	}
	info, err := s.manager.ImportOVPN(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить .ovpn: %w", err)
	}
	return &info, nil
}

func (s *Service) RemoveOVPN() error { return s.manager.RemoveOVPN() }

// CloseWindow — крестик в заголовке окна.
func (s *Service) CloseWindow() {
	if s.manager.Settings().CloseToTray {
		s.window.Hide()
		return
	}
	s.Quit()
}

func (s *Service) ShowWindow() {
	s.window.Show()
	s.window.UnMinimise()
	s.window.Focus()
}

func (s *Service) Quit() {
	s.quitting.Store(true)
	s.wapp.Quit()
}

func (s *Service) shutdown() {
	s.quitting.Store(true)
	s.manager.Disconnect()
}

// onState вызывается менеджером при каждом изменении состояния.
func (s *Service) onState(st app.State) {
	if s.wapp == nil {
		return
	}
	s.wapp.Event.Emit("state", st)
	s.refreshTray(st)
}

func (s *Service) setupTray() {
	s.menu = s.wapp.NewMenu()
	s.statusItem = s.menu.Add("Отключено").SetEnabled(false)
	s.menu.AddSeparator()
	s.toggleItem = s.menu.Add("Подключить").OnClick(func(*application.Context) { go s.manager.Toggle() })
	s.menu.Add("Открыть окно").OnClick(func(*application.Context) { s.ShowWindow() })
	s.menu.AddSeparator()
	s.russiaItem = s.menu.AddCheckbox("Российские сайты напрямую", s.manager.Settings().RussiaDirect).
		OnClick(func(ctx *application.Context) {
			settings := s.manager.Settings()
			settings.RussiaDirect = ctx.ClickedMenuItem().Checked()
			go func() {
				if err := s.manager.SaveSettings(settings); err == nil {
					s.wapp.Event.Emit("settings-changed")
				}
			}()
		})
	s.menu.Add("Журнал").OnClick(func(*application.Context) { _ = app.OpenFile(s.manager.LogFile()) })
	s.menu.AddSeparator()
	s.menu.Add("Выход").OnClick(func(*application.Context) { s.Quit() })

	s.tray = s.wapp.SystemTray.New()
	s.tray.SetIcon(icon("tray-disconnected"))
	s.tray.SetTooltip("vpn-client — отключено")
	s.tray.SetMenu(s.menu)
	s.tray.OnClick(s.ShowWindow)
	s.tray.OnDoubleClick(func() { go s.manager.Toggle() })
	s.refreshTray(s.manager.State())
}

func (s *Service) refreshTray(st app.State) {
	if s.tray == nil {
		return
	}
	s.trayMu.Lock()
	defer s.trayMu.Unlock()

	if st.Status != s.lastStatus {
		s.tray.SetIcon(icon("tray-" + string(st.Status)))
		s.lastStatus = st.Status
	}
	status := map[app.Status]string{
		app.StatusDisconnected: "Отключено",
		app.StatusConnecting:   "Подключение…",
		app.StatusConnected:    "Подключено",
		app.StatusError:        "Ошибка подключения",
	}[st.Status]

	var parts []string
	if st.Status == app.StatusConnected {
		if st.Corp.Enabled {
			parts = append(parts, "OpenVPN "+map[bool]string{true: "работает", false: "подключается"}[st.Corp.Up])
		}
		if st.Proxy.Enabled && st.Proxy.Current != "" {
			parts = append(parts, "VLESS: "+st.Proxy.Current)
		}
	}
	tooltip := "vpn-client — " + strings.ToLower(status[:1]) + status[1:]
	if len(parts) > 0 {
		tooltip += "\n" + strings.Join(parts, ", ")
	}
	if st.Status == app.StatusError && st.Error != "" {
		tooltip += "\n" + truncate(st.Error, 100)
	}
	s.tray.SetTooltip(truncate(tooltip, 127))

	s.statusItem.SetLabel(status)
	if st.Status == app.StatusConnecting || st.Status == app.StatusConnected {
		s.toggleItem.SetLabel("Отключить")
	} else {
		s.toggleItem.SetLabel("Подключить")
	}
	s.russiaItem.SetChecked(s.manager.Settings().RussiaDirect)
	s.menu.Update()
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
