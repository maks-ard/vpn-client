package app

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maks-ard/vpn-client/internal/profile"
	"github.com/maks-ard/vpn-client/internal/singbox"
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

func categoryInput(t *testing.T, m *Manager) *singbox.Input {
	t.Helper()
	s := Settings{Link: legacyVLESS, RussiaDirect: false, Categories: []profile.Category{
		{ID: "social", Preset: true, Action: profile.ActionProxy},
	}}
	prof, err := s.profile(m.paths)
	if err != nil {
		t.Fatal(err)
	}
	in, err := singbox.FromProfileOffline(prof, m.paths.Data)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(testPaths(t), func(State) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.log.Close() })
	return m
}

// Наборы категорий скачиваются до сборки конфига; недоступный набор не мешает
// подключению, а выпадает из конфига с предупреждением.
func TestPrepareRuleSets(t *testing.T) {
	ctx := context.Background()

	m := newTestManager(t)
	in := categoryInput(t, m)
	want := len(in.CategorySets())
	if want < 2 {
		t.Fatalf("у категории «Соцсети» должно быть несколько наборов, а их %d", want)
	}
	fetched := 0
	m.fetchSet = func(context.Context, string) ([]byte, error) { fetched++; return []byte("data"), nil }
	paths := m.prepareRuleSets(ctx, "", in)
	if len(paths) != want || fetched != want {
		t.Fatalf("получено наборов: %d из %d, скачиваний %d", len(paths), want, fetched)
	}
	for tag, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s: файла нет: %v", tag, err)
		}
	}
	// Повторное подключение берёт свежие копии, не скачивая заново.
	if m.prepareRuleSets(ctx, "", in); fetched != want {
		t.Errorf("свежие копии скачаны повторно: %d", fetched)
	}

	// Сеть недоступна и копий нет: набор пропущен, конфиг собирается.
	m = newTestManager(t)
	in = categoryInput(t, m)
	m.fetchSet = func(context.Context, string) ([]byte, error) { return nil, errors.New("нет сети") }
	in.LocalSets = m.prepareRuleSets(ctx, "", in)
	if len(in.LocalSets) != 0 {
		t.Fatalf("наборы без сети: %v", in.LocalSets)
	}
	if _, err := singbox.Build(in); err != nil {
		t.Fatalf("недоступные наборы не должны ломать сборку конфига: %v", err)
	}
	if warn := strings.Join(in.Warnings(), "\n"); !strings.Contains(warn, "недоступен") {
		t.Errorf("нет предупреждения: %q", warn)
	}

	// Сеть недоступна, но есть устаревшая копия: берётся она.
	m = newTestManager(t)
	in = categoryInput(t, m)
	m.fetchSet = func(context.Context, string) ([]byte, error) { return []byte("data"), nil }
	m.prepareRuleSets(ctx, "", in)
	old := time.Now().Add(-100 * time.Hour)
	for _, p := range m.prepareRuleSets(ctx, "", in) {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	m.fetchSet = func(context.Context, string) ([]byte, error) { return nil, errors.New("нет сети") }
	if got := m.prepareRuleSets(ctx, "", in); len(got) != want {
		t.Errorf("устаревшие копии не использованы: %d из %d", len(got), want)
	}
}

// Страница-заглушка вместо .srs отклоняется настоящим sing-box и не попадает в конфиг.
func TestRuleSetValidation(t *testing.T) {
	exe := os.Getenv("VPNCLIENT_SINGBOX")
	if exe == "" {
		t.Skip("VPNCLIENT_SINGBOX не задан")
	}
	m := newTestManager(t)
	in := categoryInput(t, m)
	m.fetchSet = func(context.Context, string) ([]byte, error) { return []byte("<html>captive portal</html>"), nil }
	if got := m.prepareRuleSets(context.Background(), exe, in); len(got) != 0 {
		t.Errorf("не-набор принят: %v", got)
	}
	if entries, _ := os.ReadDir(filepath.Join(m.paths.Data, "rule-sets")); len(entries) != 0 {
		t.Errorf("после отказа остались файлы: %v", entries)
	}
}
