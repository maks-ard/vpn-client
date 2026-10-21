package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Журнал больше этого размера переименовывается в .old при следующей записи.
const maxLogSize = 2 << 20

// logFile — журнал приложения и sing-box. Последние строки держит в памяти,
// чтобы показать их в сообщении об ошибке.
type logFile struct {
	path string

	mu   sync.Mutex
	f    *os.File
	size int64
	tail []string
	part string
}

func newLogFile(path string) *logFile {
	return &logFile{path: path}
}

func (l *logFile) Printf(format string, a ...any) {
	line := time.Now().Format("2006-01-02 15:04:05") + " vpnclient: " + fmt.Sprintf(format, a...) + "\n"
	_, _ = l.Write([]byte(line))
}

// Write принимает вывод sing-box.
func (l *logFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.remember(string(p))
	if err := l.open(); err != nil {
		return len(p), nil
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	if err != nil {
		return len(p), nil
	}
	return len(p), nil
}

func (l *logFile) open() error {
	if l.f != nil && l.size < maxLogSize {
		return nil
	}
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
		_ = os.Rename(l.path, l.path+".old")
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	l.f = f
	if st != nil {
		l.size = st.Size()
	}
	return nil
}

func (l *logFile) remember(s string) {
	s = l.part + s
	lines := strings.Split(s, "\n")
	l.part = lines[len(lines)-1]
	for _, line := range lines[:len(lines)-1] {
		if line = strings.TrimSpace(line); line != "" {
			l.tail = append(l.tail, line)
		}
	}
	if len(l.tail) > 50 {
		l.tail = l.tail[len(l.tail)-50:]
	}
}

// tailHint — последняя ошибка sing-box для сообщения пользователю.
func (l *logFile) tailHint() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.tail) - 1; i >= 0; i-- {
		line := l.tail[i]
		if strings.Contains(line, "FATAL") || strings.Contains(line, "ERROR") {
			if j := strings.Index(line, "] "); j >= 0 && j < 40 {
				line = line[j+2:]
			}
			return ": " + line
		}
	}
	return ""
}
