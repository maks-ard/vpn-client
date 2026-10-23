package runner

import (
	"io"
	"os"
	"os/signal"
	"strings"
	"testing"
	"time"
)

// TestMain превращает тестовый exe в подставной sing-box: он работает,
// пока не получит CTRL_BREAK.
func TestMain(m *testing.M) {
	if os.Getenv("RUNNER_TEST_CHILD") == "1" {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt)
		select {
		case <-ch:
			os.Exit(0)
		case <-time.After(time.Minute):
			os.Exit(3)
		}
	}
	os.Exit(m.Run())
}

func TestHandoffAndAdopt(t *testing.T) {
	t.Setenv("RUNNER_TEST_CHILD", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Start(Options{Exe: exe, DataDir: t.TempDir(), Output: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.sys.kill() })
	h, err := p.Handoff()
	if err != nil {
		t.Fatal(err)
	}
	if h.Job == "" || h.PID == 0 || h.Created == 0 {
		t.Fatalf("неполная передача: %+v", h)
	}
	// После передачи прежний владелец процесс не останавливает.
	p.Stop()
	select {
	case <-p.Done():
		t.Fatal("переданный процесс остановлен прежним владельцем")
	default:
	}

	for name, bad := range map[string]struct {
		h   Handoff
		exe string
	}{
		"другое время запуска": {Handoff{Job: h.Job, PID: h.PID, Created: h.Created + 1}, exe},
		"другой файл":          {h, `C:\Windows\notepad.exe`},
		"нет такого job":       {Handoff{Job: h.Job + "-x", PID: h.PID, Created: h.Created}, exe},
	} {
		if q, err := Adopt(bad.h, bad.exe); err == nil {
			q.handed.Store(true)
			t.Errorf("%s: подхват должен был не пройти", name)
		}
	}

	q, err := Adopt(h, strings.ToUpper(exe))
	if err != nil {
		t.Fatal(err)
	}
	q.Stop()
	select {
	case <-q.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("подхваченный процесс не остановился")
	}
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("исходный объект не заметил завершения процесса")
	}
}

func TestStopWithoutHandoff(t *testing.T) {
	t.Setenv("RUNNER_TEST_CHILD", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Start(Options{Exe: exe, DataDir: t.TempDir(), Output: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	p.Stop()
	select {
	case <-p.Done():
	default:
		t.Fatal("Stop вернулся до завершения процесса")
	}
	if !strings.Contains(p.Err().Error(), "sing-box") {
		t.Errorf("Err() = %v", p.Err())
	}
}
