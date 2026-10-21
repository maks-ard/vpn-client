//go:build windows

// vpnclient — VPN-клиент для Windows с окном и иконкой в трее: корпоративный
// трафик идёт через OpenVPN, зарубежный через VLESS, остальное напрямую.
package main

import (
	"embed"
	"io/fs"
	"log"
	"os"
	"slices"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/maks-ard/vpn-client/internal/app"
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
	// --autostart передаёт задача планировщика: стартуем свёрнутыми в трей.
	autostart := slices.Contains(os.Args[1:], "--autostart")

	paths, err := app.DefaultPaths()
	if err != nil {
		log.Fatal(err)
	}
	assets, err := fs.Sub(frontend, "frontend")
	if err != nil {
		log.Fatal(err)
	}

	svc := &Service{}
	wapp := application.New(application.Options{
		Name:        "vpn-client",
		Description: "VPN с раздельной маршрутизацией",
		Icon:        icon("app"),
		Services:    []application.Service{application.NewService(svc)},
		Assets:      application.AssetOptions{Handler: application.AssetFileServerFS(assets)},
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "com.github.maks-ard.vpn-client",
			// Повторный запуск (ярлык, автозапуск) просто показывает окно.
			OnSecondInstanceLaunch: func(application.SecondInstanceData) { svc.ShowWindow() },
		},
		Windows: application.WindowsOptions{},
		// Перед выходом отключаем VPN, чтобы sing-box убрал маршруты.
		OnShutdown: func() { svc.shutdown() },
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

	manager, err := app.NewManager(paths, svc.onState)
	if err != nil {
		log.Fatal(err)
	}
	svc.init(wapp, window, manager, version)

	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		if manager.Settings().CloseToTray && !svc.quitting.Load() {
			window.Hide()
			e.Cancel()
		}
	})

	svc.setupTray()

	// Подключаемся, когда приложение и трей уже готовы.
	wapp.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		if manager.Settings().ConnectOnStart {
			manager.Connect()
		}
	})

	if err := wapp.Run(); err != nil {
		log.Fatal(err)
	}
}
