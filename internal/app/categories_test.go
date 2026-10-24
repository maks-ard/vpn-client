package app

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/maks-ard/vpn-client/internal/ovpn"
	"github.com/maks-ard/vpn-client/internal/profile"
	"github.com/maks-ard/vpn-client/internal/singbox"
	"github.com/maks-ard/vpn-client/internal/subscription"
	"github.com/maks-ard/vpn-client/internal/vless"
)

const legacyVLESS = "vless://11111111-2222-3333-4444-555555555555@vless.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123456789abcdef&type=tcp#test"

// TestLegacySettingsKeepRouting проверяет главное обещание обновления: settings.json
// старого формата (без поля categories) даёт тот же конфиг sing-box, что и раньше.
// Эталон снят до появления категорий (internal/singbox/testdata/golden).
func TestLegacySettingsKeepRouting(t *testing.T) {
	p := testPaths(t)
	if err := os.MkdirAll(p.Config, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := `{
  "link": "` + legacyVLESS + `",
  "server": "",
  "ovpnUsername": "u",
  "ovpnPassword": "p",
  "corpDomains": ["corp.example.com", "office.example"],
  "russiaDirect": true,
  "autostart": false,
  "connectOnStart": false,
  "closeToTray": true
}`
	if err := os.WriteFile(p.settingsFile(), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	corp, err := os.ReadFile("../singbox/testdata/corp.ovpn")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.ovpnFile(), corp, 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := loadSettings(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Categories) != 0 {
		t.Fatalf("в старых настройках категорий быть не может: %v", s.Categories)
	}
	prof, err := s.profile(p)
	if err != nil {
		t.Fatal(err)
	}
	link, err := vless.Parse(legacyVLESS)
	if err != nil {
		t.Fatal(err)
	}
	in := &singbox.Input{Profile: prof, Servers: []subscription.Server{{Name: link.Name, Links: []*vless.Link{link}}}}
	if in.OpenVPN, err = ovpn.ParseFile(p.ovpnFile()); err != nil {
		t.Fatal(err)
	}
	got, err := singbox.Build(in)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../singbox/testdata/golden/both-russia.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Error("конфиг из настроек старого формата отличается от эталона: обновление изменило бы маршрутизацию")
	}

	// Сохранение этих же настроек новой версией тоже ничего не меняет.
	if err := s.normalize(); err != nil {
		t.Fatal(err)
	}
	prof, err = s.profile(p)
	if err != nil {
		t.Fatal(err)
	}
	in.Profile = prof
	if again, _ := singbox.Build(in); string(again) != string(want) {
		t.Error("после normalize конфиг изменился")
	}
}

func TestSettingsCategories(t *testing.T) {
	s := Settings{Categories: []profile.Category{
		{ID: "ads", Preset: true, Action: profile.ActionBlock},
		{ID: "c-1", Name: " Работа ", Action: profile.ActionProxy, Rules: []profile.Rule{{Type: profile.RuleDomain, Value: "Figma.com"}}},
	}}
	if err := s.normalize(); err != nil {
		t.Fatal(err)
	}
	if s.Categories[1].Name != "Работа" || s.Categories[1].Rules[0].Value != "figma.com" {
		t.Errorf("normalize: %+v", s.Categories)
	}
	if err := (&Settings{Categories: []profile.Category{{ID: "ads", Preset: true, Action: "x"}}}).normalize(); err == nil {
		t.Error("неизвестное направление должно отклоняться")
	}
	prof, err := (Settings{Link: legacyVLESS, Categories: s.Categories}).profile(testPaths(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(prof.Routing.Categories) != 2 {
		t.Errorf("категории не попали в профиль: %+v", prof.Routing.Categories)
	}
}

func TestRoutingChangedCategories(t *testing.T) {
	ads := profile.Category{ID: "ads", Preset: true, Action: profile.ActionBlock}
	video := profile.Category{ID: "video", Preset: true, Action: profile.ActionProxy}
	custom := profile.Category{ID: "c-1", Name: "Моя", Action: profile.ActionDirect, Rules: []profile.Rule{{Type: profile.RuleDomain, Value: "a.com"}}}
	auto := func(c profile.Category) profile.Category { c.Action = profile.ActionAuto; return c }

	cases := []struct {
		name string
		a, b []profile.Category
		want bool
	}{
		{"ничего → auto", nil, []profile.Category{auto(ads)}, false},
		{"auto → auto с другим набором", []profile.Category{auto(ads)}, []profile.Category{auto(video), auto(ads)}, false},
		{"auto → блок", []profile.Category{auto(ads)}, []profile.Category{ads}, true},
		{"другое направление", []profile.Category{ads}, []profile.Category{{ID: "ads", Preset: true, Action: profile.ActionProxy}}, true},
		{"другой порядок", []profile.Category{ads, video}, []profile.Category{video, ads}, true},
		{"переименование", []profile.Category{custom}, []profile.Category{{ID: "c-1", Name: "Другое имя", Action: profile.ActionDirect, Rules: custom.Rules}}, false},
		{"новое правило", []profile.Category{custom}, []profile.Category{{ID: "c-1", Name: "Моя", Action: profile.ActionDirect, Rules: append([]profile.Rule{{Type: profile.RuleDomain, Value: "b.com"}}, custom.Rules...)}}, true},
		{"без изменений", []profile.Category{ads, custom}, []profile.Category{ads, custom}, false},
	}
	for _, c := range cases {
		if got := routingChanged(Settings{Categories: c.a}, Settings{Categories: c.b}); got != c.want {
			t.Errorf("%s: routingChanged = %v, ожидалось %v", c.name, got, c.want)
		}
	}
}

func TestCategoryExportImport(t *testing.T) {
	cats := []profile.Category{
		{ID: "ads", Preset: true, Action: profile.ActionBlock},
		{ID: "c-1", Name: "Работа", Action: profile.ActionCorp, Rules: []profile.Rule{{Type: profile.RuleDomain, Value: "figma.com"}, {Type: profile.RuleKeyword, Value: "slack"}}},
	}
	data, err := ExportCategory(cats, "c-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExportCategory(cats, "ads"); err == nil {
		t.Error("готовую категорию экспортировать нельзя")
	}
	if _, err := ExportCategory(cats, "nope"); err == nil {
		t.Error("несуществующая категория")
	}

	c, err := ImportCategory(data, profile.ActionDirect, cats)
	if err != nil {
		t.Fatal(err)
	}
	// Направление выбирает тот, кто импортирует, а не файл.
	if c.Action != profile.ActionDirect || c.Name != "Работа (2)" || c.Preset || len(c.Rules) != 2 {
		t.Fatalf("импортировано %+v", c)
	}
	if !regexp.MustCompile(`^c-[0-9a-f]{8}$`).MatchString(c.ID) || findCategory(cats, c.ID) >= 0 {
		t.Errorf("идентификатор %q", c.ID)
	}
	if _, err := profile.NormalizeCategories(append(cats, c)); err != nil {
		t.Errorf("импортированная категория не проходит проверку: %v", err)
	}
	if _, err := ImportCategory(data, "tunnel", cats); err == nil || !strings.Contains(err.Error(), "направление") {
		t.Errorf("плохое направление: %v", err)
	}
	if _, err := ImportCategory([]byte(`{"format":"vpnclient-category","version":1,"name":"x","rules":[],"action":"corp"}`), profile.ActionCorp, cats); err == nil {
		t.Error("направление в файле не допускается")
	}
}

func TestPresets(t *testing.T) {
	list := Presets()
	if len(list) == 0 {
		t.Fatal("каталог пуст")
	}
	for _, p := range list {
		if p.ID == "" || p.Title == "" {
			t.Errorf("запись %+v", p)
		}
	}
}

// Файл настроек с категориями переживает запись и чтение без потерь.
func TestSettingsCategoriesRoundTrip(t *testing.T) {
	p := testPaths(t)
	s := defaultSettings()
	s.Categories = []profile.Category{
		{ID: "ads", Preset: true, Action: profile.ActionBlock},
		{ID: "c-1", Name: "Работа", Action: profile.ActionCorp, Rules: []profile.Rule{{Type: profile.RuleProcess, Value: "zoom.exe"}}},
	}
	if err := saveSettings(p, s); err != nil {
		t.Fatal(err)
	}
	got, err := loadSettings(p)
	if err != nil {
		t.Fatal(err)
	}
	if effectiveCategories(got.Categories) != effectiveCategories(s.Categories) || got.Categories[1].Name != "Работа" {
		t.Errorf("после чтения: %+v", got.Categories)
	}
	if _, err := os.Stat(filepath.Join(p.Config, "settings.json")); err != nil {
		t.Fatal(err)
	}
}
