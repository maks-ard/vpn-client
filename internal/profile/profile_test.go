package profile

import (
	"path/filepath"
	"testing"
)

func TestParseDefaults(t *testing.T) {
	p, err := Parse([]byte("vless: vless://id@host:443\ncorporate: {}\nrouting:\n  direct_domains: ['*.Example.COM.', ' ']\n"), "/base")
	if err != nil {
		t.Fatal(err)
	}
	if !p.RussiaDirect() || p.TUN.Stack != "mixed" || p.TUN.MTU != 9000 || p.DNS.Direct == "" || p.SingBox.LogLevel != "warn" {
		t.Errorf("значения по умолчанию не применены: %+v", p)
	}
	if len(p.Routing.DirectDomains) != 1 || p.Routing.DirectDomains[0] != "example.com" {
		t.Errorf("домены не нормализованы: %q", p.Routing.DirectDomains)
	}
	if got := p.Resolve("corp.ovpn"); got != filepath.Join("/base", "corp.ovpn") {
		t.Errorf("Resolve = %q", got)
	}
}

func TestParseRussiaDirectFalse(t *testing.T) {
	p, err := Parse([]byte("vless: vless://id@host\nrouting:\n  russia_direct: false\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	if p.RussiaDirect() {
		t.Error("russia_direct: false не учтён")
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"пустой профиль":        "{}",
		"openvpn без config":    "openvpn: {}\n",
		"corporate без openvpn": "vless: x\ncorporate:\n  domains: [a.ru]\n",
		"неверная подсеть":      "openvpn:\n  config: a.ovpn\ncorporate:\n  subnets: [10.0.0.0]\n",
		"неизвестный стек":      "vless: x\ntun:\n  stack: lwip\n",
		"неизвестное поле":      "vless: x\nvles: y\n",
		"неизвестный log_level": "vless: x\nsingbox:\n  log_level: loud\n",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src), ""); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}
