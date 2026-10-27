package singbox

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/maks-ard/vpn-client/internal/profile"
)

func testCorpLink() *CorpLink {
	return &CorpLink{
		Interface: "OpenVPN Data Channel Offload",
		DNS:       []netip.Addr{netip.MustParseAddr("fd00::53"), netip.MustParseAddr("10.8.0.1"), netip.MustParseAddr("10.8.0.2")},
		Domains:   []string{"corp.test"},
		Routes:    []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
		Servers:   []netip.Addr{netip.MustParseAddr("203.0.113.1")},
	}
}

func buildCorpLink(t *testing.T, link *CorpLink, cats ...profile.Category) (M, []byte) {
	t.Helper()
	in, err := Load(context.Background(), "testdata/profile.yaml", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	in.CorpLink = link
	in.Profile.Routing.Categories = cats
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

func findTagged(list []any, tag string) M {
	for _, item := range list {
		if m := item.(M); m["tag"] == tag {
			return m
		}
	}
	return nil
}

func TestCorpLink(t *testing.T) {
	cfg, data := buildCorpLink(t, testCorpLink(), profile.Category{Name: "Свои", Action: profile.ActionCorp,
		Rules: []profile.Rule{{Type: profile.RuleDomain, Value: "partner.example"}}})

	// Endpoint sing-box не нужен: трафик идёт в адаптер настоящего OpenVPN.
	if _, ok := cfg["endpoints"]; ok || strings.Contains(string(data), "openvpn") {
		t.Errorf("в конфиге остался OpenVPN sing-box:\n%s", data)
	}
	corp := findTagged(cfg["outbounds"].([]any), TagCorp)
	if corp == nil || corp["type"] != "direct" || corp["bind_interface"] != "OpenVPN Data Channel Offload" ||
		corp["domain_resolver"] != TagDNSCorp {
		t.Errorf("outbound corp = %v", corp)
	}

	rules := cfg["route"].(M)["rules"].([]any)
	for _, c := range []struct{ key, value string }{
		{"domain_suffix", "corp.example.com"}, // из настроек
		{"domain_suffix", "corp.test"},        // от сервера
		{"ip_cidr", "10.99.0.0/16"},           // от сервера
		{"ip_cidr", "10.10.0.0/16"},           // из настроек
		{"domain_suffix", "partner.example"},  // категория «OpenVPN»
	} {
		if got := routeOf(rules, c.key, c.value); got != TagCorp {
			t.Errorf("%s=%s → %q, ожидался corp", c.key, c.value, got)
		}
	}
	if strings.Contains(string(data), "preferred_by") {
		t.Error("preferred_by работает только с endpoint sing-box")
	}

	dns := cfg["dns"].(M)
	server := findTagged(dns["servers"].([]any), TagDNSCorp)
	if server == nil || server["type"] != "udp" || server["server"] != "10.8.0.1" ||
		server["bind_interface"] != "OpenVPN Data Channel Offload" {
		t.Errorf("dns-corp = %v", server)
	}
	dnsRules := dns["rules"].([]any)
	for _, domain := range []string{"corp.example.com", "corp.test", "partner.example"} {
		found := false
		for _, r := range dnsRules {
			rule := r.(M)
			if rule["server"] == TagDNSCorp && strings.Contains(strings.Join(toStrings(rule["domain_suffix"]), ","), domain) {
				found = true
			}
		}
		if !found {
			t.Errorf("DNS для %s не идёт в dns-corp: %v", domain, dnsRules)
		}
	}

	// Сервер OpenVPN мимо TUN, strict_route на месте.
	tun := cfg["inbounds"].([]any)[0].(M)
	if ex := toStrings(tun["route_exclude_address"]); len(ex) != 1 || ex[0] != "203.0.113.1/32" || tun["strict_route"] != true {
		t.Errorf("TUN: %v", tun)
	}
}

func TestCorpLinkOffline(t *testing.T) {
	link := testCorpLink()
	link.Interface = ""
	cfg, data := buildCorpLink(t, link, profile.Category{Name: "Свои", Action: profile.ActionCorp,
		Rules: []profile.Rule{{Type: profile.RuleDomain, Value: "partner.example"}}})

	// Пока OpenVPN не подключился, корпоративное не должно уйти через VLESS
	// или напрямую: правила остаются на месте, но отклоняют соединения.
	if strings.Contains(string(data), `"corp"`) || strings.Contains(string(data), TagDNSCorp) {
		t.Errorf("ссылки на corp без адаптера:\n%s", data)
	}
	rules := cfg["route"].(M)["rules"].([]any)
	for _, r := range rules {
		rule := r.(M)
		for _, d := range []string{"corp.example.com", "corp.test", "partner.example"} {
			if strings.Contains(strings.Join(toStrings(rule["domain_suffix"]), ","), d) && rule["action"] != "reject" {
				t.Errorf("правило для %s: %v", d, rule)
			}
		}
	}
	for _, r := range cfg["dns"].(M)["rules"].([]any) {
		rule := r.(M)
		if strings.Contains(strings.Join(toStrings(rule["domain_suffix"]), ","), "corp.test") &&
			(rule["action"] != "predefined" || rule["rcode"] != "SERVFAIL") {
			t.Errorf("DNS-правило для corp.test: %v", rule)
		}
	}
}

func TestCorpLinkWithoutDNS(t *testing.T) {
	link := testCorpLink()
	link.DNS = nil
	cfg, _ := buildCorpLink(t, link)
	if findTagged(cfg["dns"].(M)["servers"].([]any), TagDNSCorp) != nil {
		t.Error("dns-corp без DNS от сервера")
	}
	for _, r := range cfg["dns"].(M)["rules"].([]any) {
		rule := r.(M)
		if strings.Contains(strings.Join(toStrings(rule["domain_suffix"]), ","), "corp.test") && rule["server"] != TagDNSDirect {
			t.Errorf("DNS-правило для corp.test: %v", rule)
		}
	}
}

func TestSingBoxCheckCorpLink(t *testing.T) {
	exe := os.Getenv("VPNCLIENT_SINGBOX")
	if exe == "" {
		t.Skip("VPNCLIENT_SINGBOX не задан")
	}
	cats := profile.Category{Name: "Свои", Action: profile.ActionCorp,
		Rules: []profile.Rule{{Type: profile.RuleDomain, Value: "partner.example"}}}
	_, data := buildCorpLink(t, testCorpLink(), cats)
	singBoxCheck(t, exe, data)

	offline := testCorpLink()
	offline.Interface = ""
	_, data = buildCorpLink(t, offline, cats)
	singBoxCheck(t, exe, data)

	noDNS := testCorpLink()
	noDNS.DNS = nil
	_, data = buildCorpLink(t, noDNS, cats)
	singBoxCheck(t, exe, data)
}
