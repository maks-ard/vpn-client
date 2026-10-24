package singbox

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maks-ard/vpn-client/internal/profile"
	"github.com/maks-ard/vpn-client/internal/subscription"
	"github.com/maks-ard/vpn-client/internal/vless"
)

const categoriesYAML = `routing:
  categories:
    - {id: work, name: Работа, action: corp, rules: [{type: domain, value: intranet.example}, {type: cidr, value: 10.50.0.0/16}]}
    - {id: ads, preset: true, action: block}
    - {id: social, preset: true, action: proxy}
    - {id: games, preset: true, action: direct}
    - {id: video, preset: true, action: auto}
    - id: mine
      name: Мои
      action: proxy
      rules:
        - {type: keyword, value: slack}
        - {type: process, value: zoom.exe}
        - {type: ruleset, value: "https://example.com/my.srs"}
`

// categoryInput собирает вход генератора: yaml + VLESS и/или OpenVPN.
func categoryInput(t *testing.T, extra string, withVLESS, withOVPN bool) *Input {
	t.Helper()
	y := extra
	if withVLESS {
		y = "vless: \"" + goldenVLESS + "\"\n" + y
	}
	if withOVPN {
		y = "openvpn:\n  config: corp.ovpn\n  username: u\n  password: p\n" + y
	}
	p, err := profile.Parse([]byte(y), "testdata")
	if err != nil {
		t.Fatal(err)
	}
	in := &Input{Profile: p}
	if withVLESS {
		link, err := vless.Parse(goldenVLESS)
		if err != nil {
			t.Fatal(err)
		}
		in.Servers = []subscription.Server{{Name: link.Name, Links: []*vless.Link{link}}}
	}
	if withOVPN {
		if in.OpenVPN, err = loadOVPN(p); err != nil {
			t.Fatal(err)
		}
	}
	return in
}

func buildMap(t *testing.T, in *Input) (M, []byte) {
	t.Helper()
	data, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	var cfg M
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg, data
}

func ruleIndex(rules []any, match func(M) bool) int {
	for i, r := range rules {
		if match(r.(M)) {
			return i
		}
	}
	return -1
}

func hasValue(rule M, key, value string) bool {
	list, _ := rule[key].([]any)
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

func TestCategoriesRoute(t *testing.T) {
	cfg, _ := buildMap(t, categoryInput(t, categoriesYAML, true, true))
	route := cfg["route"].(M)
	rules := route["rules"].([]any)

	idx := func(key, value string) int {
		return ruleIndex(rules, func(r M) bool { return hasValue(r, key, value) })
	}
	private := ruleIndex(rules, func(r M) bool { _, ok := r["ip_is_private"]; return ok })
	ru := idx("domain_suffix", "ru")

	// Направленные в OpenVPN выше частных сетей, остальные ниже и выше России.
	for _, c := range []struct{ key, value string }{{"domain_suffix", "intranet.example"}, {"ip_cidr", "10.50.0.0/16"}} {
		i := idx(c.key, c.value)
		if i < 0 || i > private {
			t.Errorf("%s=%s на позиции %d, частные сети на %d", c.key, c.value, i, private)
		}
		if rules[i].(M)["outbound"] != TagCorp {
			t.Errorf("%s=%s → %v", c.key, c.value, rules[i])
		}
	}
	for _, c := range []struct{ key, value, outbound string }{
		{"rule_set", "geosite-telegram", TagProxy},
		{"rule_set", "geosite-steam", TagDirect},
		{"domain_keyword", "slack", TagProxy},
		{"process_name", "zoom.exe", TagProxy},
	} {
		i := idx(c.key, c.value)
		if i < private || i > ru {
			t.Errorf("%s=%s на позиции %d, ожидалось между %d и %d", c.key, c.value, i, private, ru)
			continue
		}
		if rules[i].(M)["outbound"] != c.outbound {
			t.Errorf("%s=%s → %v, ожидался %s", c.key, c.value, rules[i], c.outbound)
		}
	}

	// Реклама блокируется действием reject, без outbound.
	ads := idx("rule_set", "geosite-category-ads-all")
	if ads < 0 || rules[ads].(M)["action"] != "reject" || rules[ads].(M)["outbound"] != nil {
		t.Errorf("реклама: %v", rules[ads])
	}
	// Порядок категорий в списке — порядок правил.
	if !(idx("rule_set", "geosite-category-ads-all") < idx("rule_set", "geosite-telegram") && idx("rule_set", "geosite-telegram") < idx("rule_set", "geosite-steam")) {
		t.Error("порядок категорий нарушен")
	}
	// «Авто» ничего не добавляет.
	if idx("rule_set", "geosite-youtube") >= 0 {
		t.Error("категория с направлением auto попала в конфиг")
	}

	// Rule-set'ы: Россия, затем категории; ссылка пользователя получает свой тег.
	tags := map[string]string{}
	for _, s := range route["rule_set"].([]any) {
		tags[s.(M)["tag"].(string)] = s.(M)["url"].(string)
	}
	if tags["geosite-telegram"] != "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-telegram.srs" {
		t.Errorf("telegram: %v", tags)
	}
	if tags["geosite-category-ai-chat-!cn"] != "" {
		t.Error("набор неактивной категории попал в конфиг")
	}
	var user string
	for tag, url := range tags {
		if url == "https://example.com/my.srs" {
			user = tag
		}
	}
	if !strings.HasPrefix(user, "user-") || idx("rule_set", user) < 0 {
		t.Errorf("rule-set пользователя: %q %v", user, tags)
	}
	if route["default_http_client"] != "rule-sets" || cfg["http_clients"] == nil {
		t.Error("для скачивания rule-set'ов нужен http-клиент без VLESS")
	}
}

func TestCategoriesDNS(t *testing.T) {
	cfg, _ := buildMap(t, categoryInput(t, categoriesYAML, true, true))
	rules := cfg["dns"].(M)["rules"].([]any)
	find := func(key, value string) M {
		i := ruleIndex(rules, func(r M) bool { return hasValue(r, key, value) })
		if i < 0 {
			t.Fatalf("нет DNS-правила %s=%s", key, value)
		}
		return rules[i].(M)
	}
	if find("domain_suffix", "intranet.example")["server"] != TagDNSCorp {
		t.Error("корпоративный домен категории должен резолвиться через OpenVPN")
	}
	if find("rule_set", "geosite-telegram")["server"] != TagDNSRemote {
		t.Error("домены через VLESS должны резолвиться удалённым DNS")
	}
	if find("rule_set", "geosite-steam")["server"] != TagDNSDirect {
		t.Error("прямые домены резолвятся напрямую")
	}
	if r := find("rule_set", "geosite-category-ads-all"); r["action"] != "reject" || r["server"] != nil {
		t.Errorf("реклама в DNS: %v", r)
	}
	// Наборы по ссылке пользователя в DNS не попадают: в них могут быть IP-правила.
	for _, r := range rules {
		sets, _ := r.(M)["rule_set"].([]any)
		for _, v := range sets {
			if strings.HasPrefix(v.(string), "user-") {
				t.Errorf("пользовательский rule-set в DNS: %v", r)
			}
		}
	}
	// Корпоративные категории идут сразу после корпоративных правил, раньше остальных.
	corp := ruleIndex(rules, func(r M) bool { return hasValue(r, "domain_suffix", "intranet.example") })
	tg := ruleIndex(rules, func(r M) bool { return hasValue(r, "rule_set", "geosite-telegram") })
	if corp > tg {
		t.Error("корпоративные DNS-правила должны идти раньше остальных")
	}
}

func TestCategoriesSkippedWithoutTarget(t *testing.T) {
	// Без VLESS: категории через VLESS пропускаются, ссылок на proxy нет.
	in := categoryInput(t, categoriesYAML, false, true)
	_, data := buildMap(t, in)
	if strings.Contains(string(data), `"proxy"`) {
		t.Error("в конфиге без VLESS остались ссылки на proxy")
	}
	if warn := strings.Join(in.Warnings(), "\n"); !strings.Contains(warn, "Соцсети и мессенджеры") || !strings.Contains(warn, "Мои") {
		t.Errorf("нет замечаний о пропущенных категориях: %q", warn)
	}

	// Без OpenVPN: корпоративная категория пропускается, ссылок на corp нет.
	in = categoryInput(t, categoriesYAML, true, false)
	_, data = buildMap(t, in)
	if strings.Contains(string(data), `"corp"`) {
		t.Error("в конфиге без OpenVPN остались ссылки на corp")
	}
	if warn := strings.Join(in.Warnings(), "\n"); !strings.Contains(warn, "Работа") {
		t.Errorf("нет замечания о корпоративной категории: %q", warn)
	}
}

func TestCategoriesUnknownPreset(t *testing.T) {
	in := categoryInput(t, "routing:\n  categories:\n    - {id: from-the-future, preset: true, action: proxy}\n", true, false)
	_, data := buildMap(t, in)
	if strings.Contains(string(data), "from-the-future") {
		t.Error("неизвестная категория не должна попадать в конфиг")
	}
	if warn := strings.Join(in.Warnings(), "\n"); !strings.Contains(warn, "from-the-future") {
		t.Errorf("нет замечания: %q", warn)
	}
}

// Категории, у которых везде «Авто», не должны менять конфиг вообще.
func TestCategoriesAutoChangesNothing(t *testing.T) {
	const autos = "routing:\n  categories:\n    - {id: ads, preset: true, action: auto}\n    - {id: work, name: Работа, action: auto, rules: [{type: domain, value: intranet.example}]}\n"
	for _, c := range []struct{ vless, ovpn bool }{{true, false}, {true, true}, {false, true}} {
		_, plain := buildMap(t, categoryInput(t, "", c.vless, c.ovpn))
		_, withAuto := buildMap(t, categoryInput(t, autos, c.vless, c.ovpn))
		if string(plain) != string(withAuto) {
			t.Errorf("vless=%v ovpn=%v: конфиг изменился из-за категорий с auto", c.vless, c.ovpn)
		}
	}
}

func TestPresetsCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Presets() {
		if p.ID == "" || p.Title == "" || len(p.Sets) == 0 || seen[p.ID] {
			t.Errorf("некорректная запись каталога: %+v", p)
		}
		seen[p.ID] = true
	}
}

// TestSingBoxCheckCategories прогоняет конфиг с категориями через настоящий sing-box.
func TestSingBoxCheckCategories(t *testing.T) {
	exe := os.Getenv("VPNCLIENT_SINGBOX")
	if exe == "" {
		t.Skip("VPNCLIENT_SINGBOX не задан")
	}
	_, data := buildMap(t, categoryInput(t, categoriesYAML, true, true))
	singBoxCheck(t, exe, data)
	_, data = buildMap(t, categoryInput(t, categoriesYAML, true, false))
	singBoxCheck(t, exe, data)
	_, data = buildMap(t, categoryInput(t, categoriesYAML, false, true))
	singBoxCheck(t, exe, data)
}

// С LocalSets категории подключают наборы файлами, а недоступный набор
// пропускается с предупреждением, не ломая запуск.
func TestCategoriesLocalSets(t *testing.T) {
	const yaml = "routing:\n  russia_direct: false\n  categories:\n    - {id: social, preset: true, action: proxy}\n    - {id: ads, preset: true, action: block}\n"
	in := categoryInput(t, yaml, true, false)
	in.LocalSets = map[string]string{}
	for _, ref := range in.CategorySets() {
		if strings.Contains(ref.Tag, "telegram") || strings.Contains(ref.Tag, "instagram") {
			in.LocalSets[ref.Tag] = "/data/rule-sets/" + ref.Tag + ".srs"
		}
	}
	cfg, data := buildMap(t, in)
	route := cfg["route"].(M)
	local := map[string]string{}
	for _, s := range route["rule_set"].([]any) {
		set := s.(M)
		if set["type"] != "local" || set["url"] != nil {
			t.Errorf("ожидался local без url: %v", set)
		}
		local[set["tag"].(string)] = set["path"].(string)
	}
	if len(local) != 2 || local["geosite-telegram"] != "/data/rule-sets/geosite-telegram.srs" {
		t.Errorf("наборы: %v", local)
	}
	// Без remote-наборов http-клиент для скачивания не нужен.
	if route["default_http_client"] != nil || cfg["http_clients"] != nil {
		t.Error("для локальных наборов http-клиент не нужен")
	}
	// Категория без единого доступного набора пропущена целиком.
	if strings.Contains(string(data), "category-ads-all") {
		t.Error("недоступный набор попал в конфиг")
	}
	warn := strings.Join(in.Warnings(), "\n")
	if !strings.Contains(warn, "geosite-category-ads-all недоступен") || strings.Contains(warn, "telegram") {
		t.Errorf("предупреждения: %q", warn)
	}
	// Без LocalSets всё по-прежнему remote (vpnctl, эталоны).
	in.LocalSets = nil
	cfg, _ = buildMap(t, in)
	if cfg["route"].(M)["rule_set"].([]any)[0].(M)["type"] != "remote" {
		t.Error("без LocalSets наборы должны быть remote")
	}
}

func TestSingBoxCheckLocalSets(t *testing.T) {
	exe := os.Getenv("VPNCLIENT_SINGBOX")
	if exe == "" {
		t.Skip("VPNCLIENT_SINGBOX не задан")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "set.json")
	if err := os.WriteFile(src, []byte(`{"version":3,"rules":[{"domain_suffix":["example.net"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	srs := filepath.Join(dir, "set.srs")
	if out, err := exec.Command(exe, "rule-set", "compile", "--output", srs, src).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	in := categoryInput(t, categoriesYAML, true, true)
	in.LocalSets = map[string]string{}
	for _, ref := range in.CategorySets() {
		in.LocalSets[ref.Tag] = srs
	}
	_, data := buildMap(t, in)
	singBoxCheck(t, exe, data)
}
