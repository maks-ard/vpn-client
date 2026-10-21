//go:build windows

// vpnclient — VPN-клиент для Windows с окном и иконкой в трее: корпоративный
// трафик идёт через OpenVPN, зарубежный через VLESS, остальное напрямую.
//
// Один exe работает в нескольких ролях:
//   - без флагов — окно и трей (обычные права пользователя);
//   - --service — служба Windows, которая держит sing-box и обновляется сама;
//   - --install / --uninstall / --restart-service — обслуживание службы
//     (запускаются с правами администратора).
package main

import (
	"embed"
	"io/fs"
	"log"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"golang.org/x/sys/windows"

	"github.com/maks-ard/vpn-client/internal/winsvc"
)

var version = "dev"

//go:embed all:frontend
var frontend embed.FS

//go:embed icons
var icons embed.FS

func icon(name string) []byte {
	data, err := icons.ReadFile("icons/" + name + ".png")
	if err != nil {
		panic(err)
	}
	return data
}

func main() {
	args := os.Args[1:]
	switch {
	case slices.Contains(args, "--service") || winsvc.IsService():
		if err := winsvc.Run(version); err != nil {
			os.Exit(1)
		}
		return
	case slices.Contains(args, "--install"):
		exit(winsvc.Install())
	case slices.Contains(args, "--uninstall"):
		exit(winsvc.Uninstall())
	case slices.Contains(args, "--restart-service"):
		exit(winsvc.RestartService())
	}

	// --wait-pid: перезапуск окна (после установки или обновления) — ждём,
	// пока закроется старый экземпляр, иначе он перехватит запуск.
	if i := slices.Index(args, "--wait-pid"); i >= 0 && i+1 < len(args) {
		if pid, err := strconv.Atoi(args[i+1]); err == nil {
			waitProcess(uint32(pid), 15*time.Second)
		}
	}
	runGUI(slices.Contains(args, "--autostart"))
}

// exit завершает служебный режим. Текст ошибки окно покажет пользователю.
func exit(err error) {
	if err != nil {
		_ = os.WriteFile(installErrorFile(), []byte(err.Error()), 0o644)
		os.Exit(1)
	}
	_ = os.Remove(installErrorFile())
	os.Exit(0)
}

// installErrorFile — куда установка пишет ошибку, чтобы окно её показало.
// Папка временных файлов общая для пользователя и его повышенного процесса.
func installErrorFile() string {
	return os.TempDir() + `\vpn-client-install-error.txt`
}

func waitProcess(pid uint32, timeout time.Duration) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	_, _ = windows.WaitForSingleObject(h, uint32(timeout.Milliseconds()))
}

func runGUI(autostart bool) {
	assets, err := fs.Sub(frontend, "frontend")
	if err != nil {
		log.Fatal(err)
	}

	gui := newService(version)
	wapp := application.New(application.Options{
		Name:        "vpn-client",
		Description: "VPN с раздельной маршрутизацией",
		Icon:        icon("app"),
		Services:    []application.Service{application.NewService(gui)},
		Assets:      application.AssetOptions{Handler: application.AssetFileServerFS(assets)},
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "com.github.maks-ard.vpn-client",
			// Повторный запуск (ярлык, автозапуск) просто показывает окно.
			OnSecondInstanceLaunch: func(application.SecondInstanceData) { gui.ShowWindow() },
		},
		OnShutdown: gui.shutdown,
	})

	window := wapp.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:                       "main",
		Title:                      "vpn-client",
		Width:                      400,
		Height:                     680,
		Frameless:                  true,
		DisableResize:              true,
		Hidden:                     autostart,
		InitialPosition:            application.WindowCentered,
		BackgroundColour:           application.NewRGB(15, 17, 21),
		DefaultContextMenuDisabled: true,
		MaximiseButtonState:        application.ButtonHidden,
		URL:                        "/",
		Windows: application.WindowsWindow{
			Theme: application.Dark,
		},
	})
	gui.init(wapp, window)

	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		if gui.settings().CloseToTray && !gui.quitting.Load() {
			window.Hide()
			e.Cancel()
		}
	})
	gui.setupTray()

	wapp.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		go gui.supervise()
	})

	if err := wapp.Run(); err != nil {
		log.Fatal(err)
	}
}
