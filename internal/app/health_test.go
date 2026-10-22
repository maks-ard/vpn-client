package app

import (
	"context"
	"strings"
	"testing"
)

func TestWhileIdle(t *testing.T) {
	m, _ := NewManager(testPaths(t), nil)
	called := false
	if !m.WhileIdle(func() { called = true }) || !called {
		t.Fatal("обслуживание отключённого VPN не выполнено")
	}
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.cancel = cancel
	if m.WhileIdle(func() { t.Error("обновление во время подключения") }) {
		t.Fatal("активное подключение не защищено")
	}
}

func TestSessionOutputAuthFailure(t *testing.T) {
	m, err := NewManager(testPaths(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	m.update(func(s *State) { s.Corp.Up = true })
	t.Cleanup(func() { _ = m.log.Close() })
	o := &sessionOutput{m: m}
	for _, part := range []string{"ERROR endpoint/openvpn-client[corp]: authentication ", "failed: terminal\n"} {
		if n, err := o.Write([]byte(part)); err != nil || n != len(part) {
			t.Fatalf("Write: %d %v", n, err)
		}
	}
	s := m.State()
	if s.Corp.Up || s.Corp.Detail != corpAuthFailed || len(s.Warnings) != 1 {
		t.Fatalf("отказ авторизации не отражён: %+v", s)
	}
}

func TestHealthWarningRecovery(t *testing.T) {
	m, _ := NewManager(testPaths(t), nil)
	t.Cleanup(func() { _ = m.log.Close() })
	m.update(func(s *State) { s.Warnings = []string{"предупреждение профиля"} })
	for i := 0; i < 2; i++ {
		m.healthWarning("Прокси:", true, "Прокси: недоступен")
	}
	if len(m.State().Warnings) != 2 {
		t.Fatal("предупреждения дублируются")
	}
	m.healthWarning("Прокси:", false, "")
	if got := strings.Join(m.State().Warnings, ","); got != "предупреждение профиля" {
		t.Fatalf("после восстановления: %s", got)
	}
}
