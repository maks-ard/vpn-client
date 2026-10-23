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
	"sync"
	"sync/atomic"
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

// Process — запущенный нами или подхваченный у прошлой версии службы sing-box.
type Process struct {
	sys     *osProcess
	done    chan struct{}
	err     error
	handed  atomic.Bool
	stopped sync.Once
}

// Handoff описывает sing-box, который продолжает работать после выхода
// своего владельца: новая версия службы находит его и берёт под управление.
type Handoff struct {
	// Job — имя Job Object: пока его держит хоть один процесс, sing-box жив.
	Job string `json:"job"`
	PID int    `json:"pid"`
	// Created — время запуска процесса, чтобы не перепутать его с чужим
	// процессом, получившим тот же PID.
	Created int64 `json:"created"`
}

// Start запускает sing-box. Остановить его нужно через Stop или Handoff.
func Start(opts Options) (*Process, error) {
	cmd := exec.Command(opts.Exe, "run", "-c", "stdin", "-D", opts.DataDir, "--disable-color")
	cmd.Stdin = bytes.NewReader(opts.Config)
	cmd.Stdout = opts.Output
	cmd.Stderr = opts.Output
	prepare(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("запуск sing-box: %w", err)
	}
	p := &Process{sys: attach(cmd), done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		if err != nil {
			err = fmt.Errorf("sing-box завершился: %w", err)
		} else {
			err = errors.New("sing-box неожиданно завершился")
		}
		p.finish(err)
	}()
	return p, nil
}

// Adopt берёт под управление sing-box, переданный через Handoff. exe — путь,
// с которого процесс обязан быть запущен.
func Adopt(h Handoff, exe string) (*Process, error) {
	sys, err := adopt(h, exe)
	if err != nil {
		return nil, fmt.Errorf("подхват sing-box: %w", err)
	}
	p := &Process{sys: sys, done: make(chan struct{})}
	go func() {
		code, err := sys.wait()
		switch {
		case err != nil:
			err = fmt.Errorf("sing-box: ожидание завершения: %w", err)
		case code != 0:
			err = fmt.Errorf("sing-box завершился с кодом %d", code)
		default:
			err = errors.New("sing-box неожиданно завершился")
		}
		p.finish(err)
	}()
	return p, nil
}

func (p *Process) finish(err error) {
	p.err = err
	// Переданный job закрывать нельзя, пока новый владелец его не открыл:
	// дескриптор закроется вместе с нашим процессом.
	if !p.handed.Load() {
		p.sys.close()
	}
	close(p.done)
}

// Done закрывается, когда sing-box завершился.
func (p *Process) Done() <-chan struct{} { return p.done }

// Err — причина завершения; вызывать после Done.
func (p *Process) Err() error {
	<-p.done
	return p.err
}

// Stop просит sing-box завершиться, чтобы он успел убрать маршруты и
// TUN-адаптер, и ждёт его. Не ответивший за stopTimeout процесс убивается.
func (p *Process) Stop() {
	if p.handed.Load() {
		return
	}
	p.stopped.Do(func() {
		select {
		case <-p.done:
			return
		default:
		}
		if err := p.sys.interrupt(); err != nil {
			_ = p.sys.kill()
		}
		select {
		case <-p.done:
		case <-time.After(stopTimeout):
			_ = p.sys.kill()
			<-p.done
		}
	})
}

// Handoff отпускает sing-box: он продолжит работать после выхода этого
// процесса, если до тех пор кто-то откроет его job по имени.
func (p *Process) Handoff() (Handoff, error) {
	h, err := p.sys.handoff()
	if err != nil {
		return Handoff{}, fmt.Errorf("передача sing-box: %w", err)
	}
	p.handed.Store(true)
	return h, nil
}

// Run запускает sing-box и ждёт, пока он не завершится или не отменят ctx.
// При отмене ctx sing-box получает сигнал на корректное завершение, чтобы
// успеть убрать маршруты и TUN-адаптер.
func Run(ctx context.Context, opts Options) error {
	p, err := Start(opts)
	if err != nil {
		return err
	}
	select {
	case <-p.Done():
		return p.Err()
	case <-ctx.Done():
	}
	p.Stop()
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
