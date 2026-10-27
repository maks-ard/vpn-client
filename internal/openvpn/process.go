package openvpn

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync"

	"github.com/maks-ard/vpn-client/internal/runner"
)

// ErrNotFound — OpenVPN не установлен.
var ErrNotFound = errors.New("OpenVPN не найден: установите OpenVPN Community с openvpn.net")

type Options struct {
	// Exe — путь к openvpn.exe.
	Exe string
	// Config — конфиг из Config. Передаётся через stdin, чтобы ключи и
	// пароль не оставались на диске.
	Config []byte
	// Dir — рабочий каталог OpenVPN.
	Dir string
	// Output — куда писать журнал OpenVPN.
	Output io.Writer
	// OnEvent вызывается, когда туннель поднялся, упал или сервер отклонил
	// авторизацию. Вызывается из горутины чтения журнала.
	OnEvent func(Event)
}

// Start запускает OpenVPN. Остановить его нужно через Stop: тогда OpenVPN
// успевает убрать свои маршруты.
func Start(opts Options) (*runner.Process, error) {
	args := append(platformArgs(), "--config", "stdin")
	cmd := exec.Command(opts.Exe, args...)
	cmd.Dir = opts.Dir
	cmd.Stdin = bytes.NewReader(opts.Config)
	var watcher Watcher
	out := &lineWriter{w: opts.Output, fn: func(line string) {
		if ev, ok := watcher.Feed(line); ok && opts.OnEvent != nil {
			opts.OnEvent(ev)
		}
	}}
	cmd.Stdout, cmd.Stderr = out, out
	return runner.Exec(cmd, "OpenVPN")
}

// lineWriter пишет журнал как есть и отдаёт fn завершённые строки.
type lineWriter struct {
	w    io.Writer
	fn   func(string)
	mu   sync.Mutex
	part string
}

func (l *lineWriter) Write(p []byte) (int, error) {
	n, err := l.w.Write(p)
	l.mu.Lock()
	defer l.mu.Unlock()
	lines := strings.Split(l.part+string(p), "\n")
	l.part = lines[len(lines)-1]
	if len(l.part) > 64<<10 {
		l.part = ""
	}
	for _, line := range lines[:len(lines)-1] {
		l.fn(strings.TrimRight(line, "\r"))
	}
	return n, err
}
