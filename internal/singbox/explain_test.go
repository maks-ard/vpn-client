package singbox

import (
	"errors"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	good := map[string]string{
		"Example.COM":       "example.com",
		"  m.youtube.com. ": "m.youtube.com",
		"https://user:pw@Docs.Example.com:8443/a/b?c=1": "docs.example.com",
		"example.com:443":   "example.com",
		"example.com/path":  "example.com",
		"*.example.com":     "example.com",
		"8.8.8.8":           "8.8.8.8",
		"8.8.8.8:53":        "8.8.8.8",
		"[2001:db8::1]:443": "2001:db8::1",
		"2001:db8::1":       "2001:db8::1",
		"::ffff:1.2.3.4":    "1.2.3.4",
	}
	for in, want := range good {
		got, err := ParseTarget(in)
		if err != nil || got != want {
			t.Errorf("ParseTarget(%q) = %q, %v; ожидалось %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "  ", "пример.рф", "a b.com", "..", ".com", "exa mple", "http://"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("ParseTarget(%q) должен вернуть ошибку", bad)
		}
	}
}

// setsMatcher — набор тегов → домены и подсети, которые в них входят.
func setsMatcher(sets map[string][]string) SetMatcher {
	return func(tag, url, target string) (bool, error) {
		if tag == "broken" {
			return false, errors.New("файл повреждён")
		}
		for _, s := range sets[tag] {
			if target == s || strings.HasSuffix(target, "."+s) {
				return true, nil
			}
		}
		return false, nil
	}
}

func TestExplain(t *testing.T) {
	in := categoryInput(t, categoriesYAML+"corporate:\n  domains: [corp.example.com]\n  subnets: [10.10.0.0/16]\n", true, true)
	match := setsMatcher(map[string][]string{
		"geosite-telegram":         {"telegram.org", "t.me"},
		"geosite-steam":            {"steampowered.com"},
		"geosite-category-ads-all": {"ads.example"},
		"geosite-category-ru":      {"ya.ru", "gosuslugi.ru"},
		"geoip-ru":                 {"77.88.8.8"},
	})
	cases := []struct {
		target, action, ruleHas string
	}{
		{"intranet.example", "corp", "Работа"},
		{"wiki.corp.example.com", "corp", "корпоративные домены"},
		{"10.10.5.5", "corp", "корпоративные подсети"},
		{"10.50.1.1", "corp", "Работа"},
		{"192.168.1.10", "direct", "локальная сеть"},
		{"web.telegram.org", "proxy", "Соцсети"},
		{"cdn.steampowered.com", "direct", "Игры"},
		{"ads.example", "block", "Реклама"},
		{"my-slack-bot.net", "proxy", "Мои"},
		{"example.org", "proxy", ""}, // остальное → VLESS
		{"ya.ru", "direct", "российские"},
		{"example.ru", "direct", "российские"},
	}
	for _, c := range cases {
		v, err := Explain(in, c.target, match)
		if err != nil {
			t.Fatalf("%s: %v", c.target, err)
		}
		if v.Action != c.action || !strings.Contains(v.Rule, c.ruleHas) {
			t.Errorf("%s → %s по %q; ожидалось %s по %q", c.target, v.Action, v.Rule, c.action, c.ruleHas)
		}
	}
}

func TestExplainNotes(t *testing.T) {
	in := categoryInput(t, categoriesYAML, true, true)
	v, err := Explain(in, "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(v.Notes, "\n")
	for _, want := range []string{"сервер OpenVPN", "Готовые наборы"} {
		if !strings.Contains(joined, want) {
			t.Errorf("нет замечания %q в %q", want, joined)
		}
	}

	// Ошибка набора не роняет проверку, а попадает в замечания.
	in = categoryInput(t, "routing:\n  categories:\n    - {id: m, name: M, action: proxy, rules: [{type: ruleset, value: \"https://example.com/broken.srs\"}]}\n", true, false)
	v, err = Explain(in, "example.org", func(tag, url, target string) (bool, error) { return false, errors.New("файл повреждён") })
	if err != nil || v.Action != "proxy" || !strings.Contains(strings.Join(v.Notes, "\n"), "файл повреждён") {
		t.Errorf("v=%+v err=%v", v, err)
	}

	// IP-наборы для домена не проверяются, и это оговаривается.
	in = categoryInput(t, "", true, false)
	v, _ = Explain(in, "example.org", setsMatcher(nil))
	if !strings.Contains(strings.Join(v.Notes, "\n"), "наборы IP-адресов") {
		t.Errorf("нет замечания про IP-наборы: %v", v.Notes)
	}
	if v, _ = Explain(in, "77.88.8.8", setsMatcher(map[string][]string{"geoip-ru": {"77.88.8.8"}})); v.Action != "direct" {
		t.Errorf("российский IP: %+v", v)
	}
}

func TestExplainWithoutVLESS(t *testing.T) {
	in := categoryInput(t, "", false, true)
	v, err := Explain(in, "example.org", nil)
	if err != nil || v.Action != "direct" {
		t.Errorf("без VLESS остальное идёт напрямую: %+v %v", v, err)
	}
	if _, err := Explain(in, "", nil); err == nil {
		t.Error("пустой адрес")
	}
}

// Проверка адреса не должна расходиться с конфигом: правило, которое вернул
// Explain, обязано присутствовать в route.rules с тем же исходом.
func TestExplainAgreesWithConfig(t *testing.T) {
	in := categoryInput(t, categoriesYAML, true, true)
	cfg, _ := buildMap(t, in)
	rules := cfg["route"].(M)["rules"].([]any)
	v, err := Explain(in, "intranet.example", nil)
	if err != nil || v.Action != "corp" {
		t.Fatalf("%+v %v", v, err)
	}
	i := ruleIndex(rules, func(r M) bool { return hasValue(r, "domain_suffix", "intranet.example") })
	if i < 0 || rules[i].(M)["outbound"] != TagCorp {
		t.Errorf("в конфиге нет соответствующего правила: %v", rules)
	}
}
