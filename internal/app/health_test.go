package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	go func() { done <- m.session(ctx, Settings{}, nil) }()
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
	checks := m.State().Proxy.Checks
	if len(checks) != 4 || checks[3].OK || checks[3].Name != "Claude" || checks[0].CheckedAt.IsZero() {
		t.Fatalf("неверные результаты проверок: %v", checks)
	}
	if len(warnings) != 1 || !strings.HasPrefix(warnings[0], "Claude:") {
		t.Fatalf("неверное предупреждение: %v", warnings)
	}
}

func TestStateSnapshot(t *testing.T) {
	m, _ := NewManager(testPaths(t), nil)
	t.Cleanup(func() { _ = m.log.Close() })
	m.update(func(s *State) { s.Proxy.Servers = []Server{{Name: "original"}} })
	snapshot := m.State()
	snapshot.Proxy.Servers[0].Name = "changed"
	if m.State().Proxy.Servers[0].Name != "original" {
		t.Fatal("снимок изменил состояние менеджера")
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
	o := newSessionOutput(m)
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

func TestSessionOutputCorpTerminated(t *testing.T) {
	m, _ := NewManager(testPaths(t), nil)
	t.Cleanup(func() { _ = m.log.Close() })
	o := newSessionOutput(m)
	_, _ = o.Write([]byte("ERROR endpoint/openvpn-client[corp]: session failed; retrying\n"))
	if down, _ := o.corpTerminated(); down {
		t.Fatal("повторяемая ошибка принята за завершение OpenVPN")
	}
	_, _ = o.Write([]byte("ERROR endpoint/openvpn-client[corp]: client terminated: authentication failed: terminal (auth-retry none)\n"))
	if down, auth := o.corpTerminated(); !down || !auth {
		t.Fatalf("завершение не распознано: down=%v auth=%v", down, auth)
	}
}

func TestCorpRetryLimit(t *testing.T) {
	m, _ := NewManager(testPaths(t), nil)
	t.Cleanup(func() { _ = m.log.Close() })
	for i := 0; i < maxCorpRetries; i++ {
		if !m.allowCorpRetry() {
			t.Fatalf("попытка %d запрещена", i+1)
		}
	}
	if m.allowCorpRetry() {
		t.Fatal("повторы не ограничены")
	}
}

// fakeClash отвечает как Clash API sing-box: сервер "bad" ничего не открывает,
// "slow" открывает всё медленно, "partial" — всё, кроме Claude.
func fakeClash(t *testing.T, now string) (*clash, *string) {
	selected := now
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/proxies":
			_, _ = w.Write([]byte(`{"proxies":{"proxy":{"type":"Selector","now":"` + selected + `","all":["auto","bad","slow","partial"]}}}`))
		case r.Method == http.MethodPut && r.URL.Path == "/proxies/proxy":
			var body struct{ Name string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			selected = body.Name
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/delay"):
			name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/proxies/"), "/delay")
			target := r.URL.Query().Get("url")
			if name == "bad" || name == "proxy" && selected == "bad" || name == "partial" && strings.Contains(target, "claude.ai") {
				http.Error(w, `{"message":"timeout"}`, http.StatusServiceUnavailable)
				return
			}
			delay := 100
			if name == "slow" {
				delay = 900
			}
			_, _ = w.Write([]byte(`{"delay":` + strconv.Itoa(delay) + `}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &clash{base: srv.URL, http: srv.Client()}, &selected
}

func TestBestServerPrefersMoreServices(t *testing.T) {
	api, _ := fakeClash(t, "bad")
	if got, _ := bestServer(context.Background(), api, []string{"bad", "partial", "slow"}); got != "slow" {
		t.Fatalf("выбран %q вместо сервера, открывающего все сервисы", got)
	}
	if got, _ := bestServer(context.Background(), api, []string{"bad"}); got != "" {
		t.Fatalf("выбран неработающий сервер %q", got)
	}
}

func TestFailoverKeepsAutoSelection(t *testing.T) {
	m, _ := NewManager(testPaths(t), nil)
	t.Cleanup(func() { _ = m.log.Close() })
	api, selected := fakeClash(t, "bad")
	if !m.failover(context.Background(), api) || *selected != "slow" {
		t.Fatalf("переключение не выполнено: %q", *selected)
	}
	m.refreshProxies(context.Background(), api)
	if p := m.State().Proxy; p.Selected != "auto" || p.Current != "slow" {
		t.Fatalf("выбор пользователя «авто» потерян: selected=%q current=%q", p.Selected, p.Current)
	}

	m.settings.Server = "bad"
	*selected = "bad"
	if m.failover(context.Background(), api) || *selected != "bad" {
		t.Fatal("ручной выбор сервера заменён автоматически")
	}
}

// Сервер, через который не открывается часть сервисов (выход в России:
// YouTube есть, Claude нет), в «авто» меняется на открывающий всё.
func TestFailoverLeavesPartialServer(t *testing.T) {
	m, _ := NewManager(testPaths(t), nil)
	t.Cleanup(func() { _ = m.log.Close() })
	api, selected := fakeClash(t, "partial")
	if !m.failover(context.Background(), api) || *selected != "slow" {
		t.Fatalf("частично работающий сервер не заменён: %q", *selected)
	}
	// Сервер, лучше которого нет, не меняется на равный по задержке.
	if m.failover(context.Background(), api) || *selected != "slow" {
		t.Fatalf("сервер заменён без выигрыша: %q", *selected)
	}
}
