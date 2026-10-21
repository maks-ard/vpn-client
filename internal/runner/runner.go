// Package runner запускает sing-box и аккуратно останавливает его.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// stopTimeout — сколько ждать корректного завершения sing-box перед kill.
const stopTimeout = 5 * time.Second

type Options struct {
	// Exe — путь к sing-box.
	Exe string
	// Config — JSON-конфиг. Передаётся через stdin, чтобы ключи и пароли
	// не оставались на диске.
	Config []byte
	// DataDir — рабочий каталог sing-box (cache.db и т.п.).
	DataDir string
	// Output — куда писать лог sing-box.
	Output io.Writer
}

// Run запускает sing-box и ждёт, пока он не завершится или не отменят ctx.
// При отмене ctx sing-box получает сигнал на корректное завершение, чтобы
// успеть убрать маршруты и TUN-адаптер.
func Run(ctx context.Context, opts Options) error {
	cmd := exec.Command(opts.Exe, "run", "-c", "stdin", "-D", opts.DataDir, "--disable-color")
	cmd.Stdin = bytes.NewReader(opts.Config)
	cmd.Stdout = opts.Output
	cmd.Stderr = opts.Output
	prepare(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск sing-box: %w", err)
	}
	cleanup := attach(cmd)
	defer cleanup()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("sing-box завершился: %w", err)
		}
		return errors.New("sing-box неожиданно завершился")
	case <-ctx.Done():
	}

	if err := interrupt(cmd); err != nil {
		_ = cmd.Process.Kill()
	}
	select {
	case <-done:
	case <-time.After(stopTimeout):
		_ = cmd.Process.Kill()
		<-done
	}
	return nil
}

type Version struct {
	Major, Minor, Patch int
	Tags                []string
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v Version) AtLeast(major, minor int) bool {
	return v.Major > major || (v.Major == major && v.Minor >= minor)
}

func (v Version) HasTag(tag string) bool {
	for _, t := range v.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

var versionRe = regexp.MustCompile(`sing-box version (\d+)\.(\d+)\.(\d+)`)

// GetVersion вызывает `sing-box version` и разбирает ответ.
func GetVersion(exe string) (Version, error) {
	out, err := exec.Command(exe, "version").Output()
	if err != nil {
		return Version{}, fmt.Errorf("%s version: %w", exe, err)
	}
	return parseVersion(string(out))
}

func parseVersion(out string) (Version, error) {
	m := versionRe.FindStringSubmatch(out)
	if m == nil {
		return Version{}, fmt.Errorf("не удалось определить версию sing-box: %q", strings.TrimSpace(out))
	}
	var v Version
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	v.Patch, _ = strconv.Atoi(m[3])
	for _, line := range strings.Split(out, "\n") {
		if tags, ok := strings.CutPrefix(strings.TrimSpace(line), "Tags:"); ok {
			for _, t := range strings.Split(tags, ",") {
				if t = strings.TrimSpace(t); t != "" {
					v.Tags = append(v.Tags, t)
				}
			}
		}
	}
	return v, nil
}

// Check прогоняет конфиг через `sing-box check`.
func Check(exe string, config []byte, dataDir string) error {
	cmd := exec.Command(exe, "check", "-c", "stdin", "-D", dataDir, "--disable-color")
	cmd.Stdin = bytes.NewReader(config)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box check: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
