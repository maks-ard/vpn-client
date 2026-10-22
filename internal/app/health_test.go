package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReconnectPauseCancellation(t *testing.T) {
	m, _ := NewManager(testPaths(t), nil)
	t.Cleanup(func() { _ = m.log.Close() })
	m.nextConnect = time.Now().Add(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- m.session(ctx, Settings{}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("отмена зависла на паузе переподключения")
	}
}

func TestServiceProbes(t *testing.T) {
	m, _ := NewManager(testPaths(t), nil)
	t.Cleanup(func() { _ = m.log.Close() })
	var mu sync.Mutex
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		mu.Lock()
		seen[target] = true
		mu.Unlock()
		if strings.Contains(target, "claude.ai") {
			http.Error(w, `{"message":"недоступен"}`, http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"delay":100}`))
	}))
	defer srv.Close()
	m.checkServices(context.Background(), &clash{base: srv.URL, http: srv.Client()})
	if len(seen) != 4 {
		t.Fatalf("проверено %d сервисов вместо 4", len(seen))
	}
	warnings := m.State().Warnings
	if len(warnings) != 1 || !strings.HasPrefix(warnings[0], "Claude:") {
		t.Fatalf("неверное предупреждение: %v", warnings)
	}
}

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
