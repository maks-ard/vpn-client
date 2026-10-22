package app

import (
	"errors"
	"testing"
)

func TestInstallWhileIdle(t *testing.T) {
	m, _ := NewManager(testPaths(t), nil)
	t.Cleanup(func() { _ = m.log.Close() })
	want := errors.New("ошибка замены")
	attempted, err := m.InstallWhileIdle(func() error { return want })
	if !attempted || !errors.Is(err, want) || m.updating {
		t.Fatalf("ошибка не должна блокировать повтор: %v %v", attempted, err)
	}
	attempted, err = m.InstallWhileIdle(func() error { return nil })
	if !attempted || err != nil {
		t.Fatalf("%v %v", attempted, err)
	}
	m.Connect()
	if m.Active() {
		t.Fatal("подключение началось во время перезапуска")
	}
	attempted, _ = m.InstallWhileIdle(func() error { t.Fatal("повторная установка"); return nil })
	if attempted {
		t.Fatal("установка запущена повторно")
	}
}
