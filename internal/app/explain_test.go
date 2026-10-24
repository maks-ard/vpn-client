package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maks-ard/vpn-client/internal/profile"
)

// TestManagerExplain проверяет проверку адреса целиком: настройки → правила →
// настоящий sing-box сопоставляет домен с набором, скачанным (подменой) по ссылке.
func TestManagerExplain(t *testing.T) {
	exe := os.Getenv("VPNCLIENT_SINGBOX")
	if exe == "" {
		t.Skip("VPNCLIENT_SINGBOX не задан")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "list.json")
	if err := os.WriteFile(src, []byte(`{"version":3,"rules":[{"domain_suffix":["listed.example"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	srs := filepath.Join(dir, "list.srs")
	if out, err := exec.Command(exe, "rule-set", "compile", "--output", srs, src).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	data, err := os.ReadFile(srs)
	if err != nil {
		t.Fatal(err)
	}

	m, err := NewManager(testPaths(t), func(State) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.log.Close() })
	m.singBoxPath = exe
	fetches := 0
	m.fetchSet = func(ctx context.Context, url string) ([]byte, error) {
		fetches++
		if url != "https://sets.example/list.srs" {
			t.Errorf("скачивается %q", url)
		}
		return data, nil
	}

	s := Settings{Link: legacyVLESS, RussiaDirect: false, Categories: []profile.Category{
		{ID: "c-1", Name: "Список", Action: profile.ActionDirect, Rules: []profile.Rule{{Type: profile.RuleSet, Value: "https://sets.example/list.srs"}}},
	}}
	ctx := context.Background()

	v, err := m.Explain(ctx, s, "a.listed.example")
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != "direct" || !strings.Contains(v.Rule, "Список") {
		t.Errorf("домен из набора: %+v", v)
	}
	v, err = m.Explain(ctx, s, "https://other.example/page")
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != "proxy" || v.Rule != "" {
		t.Errorf("домен вне набора должен идти через VLESS: %+v", v)
	}
	if fetches != 1 {
		t.Errorf("набор должен скачиваться один раз и кэшироваться, скачано %d", fetches)
	}

	// Ошибки настроек доходят до пользователя.
	if _, err := m.Explain(ctx, Settings{}, "example.com"); err == nil || !strings.Contains(err.Error(), "подписку") {
		t.Errorf("пустые настройки: %v", err)
	}
	if _, err := m.Explain(ctx, s, "пример.рф"); err == nil {
		t.Error("кириллица должна отклоняться")
	}
}
