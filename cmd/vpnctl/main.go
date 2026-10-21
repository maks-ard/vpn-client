// vpnctl — консольная утилита для разработки: проверяет профиль, выводит
// конфиг sing-box и запускает его без GUI. Пользовательское приложение —
// cmd/vpnclient. Разводит трафик так же:
// корпоративный — через OpenVPN, зарубежный — через VLESS, остальное напрямую.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/maks-ard/vpn-client/internal/runner"
	"github.com/maks-ard/vpn-client/internal/singbox"
	"github.com/maks-ard/vpn-client/internal/singboxbin"
)

var version = "dev"

const usage = `vpnctl — раздельная маршрутизация через sing-box (утилита разработчика)

Использование:
  vpnctl run    [-p профиль]  подключиться (нужны права администратора), Ctrl+C — отключиться
  vpnctl check  [-p профиль]  проверить профиль и сгенерированный конфиг
  vpnctl config [-p профиль] [-o файл]  вывести конфиг sing-box
  vpnctl version

По умолчанию профиль — profile.yaml рядом с vpnctl.exe.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "run":
		err = cmdRun(args)
	case "check":
		err = cmdCheck(args)
	case "config":
		err = cmdConfig(args)
	case "version", "-v", "--version":
		fmt.Println("vpnctl", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

type common struct {
	profile string
	exeDir  string
}

func parseFlags(name string, args []string, extra func(*flag.FlagSet)) (*common, error) {
	exeDir := "."
	if exe, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exe)
	}
	c := &common{exeDir: exeDir}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&c.profile, "p", filepath.Join(exeDir, "profile.yaml"), "путь к профилю")
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return c, nil
}

// load читает профиль, собирает конфиг и печатает предупреждения.
func (c *common) load() (*singbox.Input, []byte, error) {
	dataDir, err := c.dataDir()
	if err != nil {
		return nil, nil, err
	}
	in, err := singbox.Load(context.Background(), c.profile, dataDir)
	if err != nil {
		return nil, nil, err
	}
	for _, w := range in.Warnings() {
		fmt.Fprintln(os.Stderr, "предупреждение:", w)
	}
	cfg, err := singbox.Build(in)
	if err != nil {
		return nil, nil, err
	}
	return in, cfg, nil
}

// singBox возвращает путь к sing-box. Релизная сборка несёт его внутри себя
// и распаковывает в data; release нужно вызвать после остановки sing-box.
func (c *common) singBox(in *singbox.Input) (path string, release func(), err error) {
	if p := in.Profile.SingBox.Path; p != "" {
		return in.Profile.Resolve(p), func() {}, nil
	}
	if data := singboxbin.Data(); data != nil {
		dir, err := c.dataDir()
		if err != nil {
			return "", nil, err
		}
		return runner.Install(dir, data)
	}
	name := "sing-box"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(c.exeDir, name), func() {}, nil
}

func (c *common) dataDir() (string, error) {
	dir := filepath.Join(c.exeDir, "data")
	return dir, os.MkdirAll(dir, 0o700)
}

// checkSingBox проверяет, что sing-box подходящей версии и собран с OpenVPN.
func checkSingBox(exe string, in *singbox.Input) error {
	v, err := runner.GetVersion(exe)
	if err != nil {
		return fmt.Errorf("sing-box не найден или не запускается (%w); скачайте его скриптом scripts/fetch-singbox.ps1", err)
	}
	if !v.AtLeast(1, 14) {
		return fmt.Errorf("нужен sing-box %s или новее, найден %s", singbox.MinVersion, v)
	}
	if in.OpenVPN != nil && len(v.Tags) > 0 && !v.HasTag("with_openvpn") {
		return errors.New("sing-box собран без поддержки OpenVPN (тег with_openvpn), возьмите официальную сборку")
	}
	return nil
}

func cmdRun(args []string) error {
	c, err := parseFlags("run", args, nil)
	if err != nil {
		return err
	}
	in, cfg, err := c.load()
	if err != nil {
		return err
	}
	if !runner.IsElevated() {
		return errors.New("для TUN нужны права администратора: запустите консоль от имени администратора")
	}
	exe, release, err := c.singBox(in)
	if err != nil {
		return err
	}
	defer release()
	if err := checkSingBox(exe, in); err != nil {
		return err
	}
	dataDir, err := c.dataDir()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintln(os.Stderr, "подключение... (Ctrl+C — отключиться)")
	err = runner.Run(ctx, runner.Options{Exe: exe, Config: cfg, DataDir: dataDir, Output: os.Stdout})
	if err == nil {
		fmt.Fprintln(os.Stderr, "отключено")
	}
	return err
}

func cmdCheck(args []string) error {
	c, err := parseFlags("check", args, nil)
	if err != nil {
		return err
	}
	in, cfg, err := c.load()
	if err != nil {
		return err
	}
	exe, release, err := c.singBox(in)
	if err != nil {
		return err
	}
	defer release()
	if err := checkSingBox(exe, in); err != nil {
		return err
	}
	dataDir, err := c.dataDir()
	if err != nil {
		return err
	}
	if err := runner.Check(exe, cfg, dataDir); err != nil {
		return err
	}
	fmt.Println("профиль в порядке")
	return nil
}

func cmdConfig(args []string) error {
	var out string
	c, err := parseFlags("config", args, func(fs *flag.FlagSet) {
		fs.StringVar(&out, "o", "", "записать в файл вместо stdout (в конфиге есть ключи и пароли!)")
	})
	if err != nil {
		return err
	}
	_, cfg, err := c.load()
	if err != nil {
		return err
	}
	cfg = append(cfg, '\n')
	if out == "" {
		_, err = os.Stdout.Write(cfg)
		return err
	}
	return os.WriteFile(out, cfg, 0o600)
}
