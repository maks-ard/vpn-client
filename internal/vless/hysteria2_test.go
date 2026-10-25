package vless

import (
	"fmt"
	"testing"
)

func TestParseHysteria2(t *testing.T) {
	l, err := ParseLink("hysteria2://p%40ss@hy.example.com:8443/?sni=cdn.example.com&obfs=salamander&obfs-password=secret&insecure=1#%D0%A4%D0%B8%D0%BD%D0%BB%D1%8F%D0%BD%D0%B4%D0%B8%D1%8F")
	if err != nil {
		t.Fatal(err)
	}
	if l.Protocol != "hysteria2" || l.Server != "hy.example.com" || l.Port != 8443 || l.Password != "p@ss" || l.Name != "Финляндия" {
		t.Errorf("адрес/пароль: %+v", l)
	}
	if l.SNI != "cdn.example.com" || !l.Insecure || l.Obfs != "salamander" || l.ObfsPassword != "secret" || l.ServerPorts != nil {
		t.Errorf("tls/obfs: %+v", l)
	}
}

func TestParseHysteria2Variants(t *testing.T) {
	for _, tc := range []struct {
		link, want string
	}{
		{"hy2://pass@1.2.3.4", "1.2.3.4 443 [] pass "},
		{"hysteria2://user:pw@h.example.com:443,20000-30000?obfs=none", "h.example.com 443 [443:443 20000:30000] user:pw h.example.com"},
		{"hysteria2://pass@h.example.com:20000-30000/", "h.example.com 20000 [20000:30000] pass h.example.com"},
		{"hysteria2://pass@h.example.com:443?mport=5000-6000", "h.example.com 443 [443:443 5000:6000] pass h.example.com"},
		{"hysteria2://pass@[2001:db8::1]:443", "2001:db8::1 443 [] pass "},
	} {
		l, err := ParseLink(tc.link)
		if err != nil {
			t.Errorf("%s: %v", tc.link, err)
			continue
		}
		if got := fmt.Sprint(l.Server, " ", l.Port, " ", l.ServerPorts, " ", l.Password, " ", l.SNI); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.link, got, tc.want)
		}
	}
}

func TestParseHysteria2Errors(t *testing.T) {
	for _, link := range []string{
		"hysteria2://h.example.com:443",
		"hysteria2://pass@:443",
		"hysteria2://pass@h.example.com:0",
		"hysteria2://pass@h.example.com:3000-2000",
		"hysteria2://pass@h.example.com:443?obfs=salamander",
		"hysteria2://pass@h.example.com:443?obfs=unknown&obfs-password=x",
	} {
		if _, err := ParseLink(link); err == nil {
			t.Errorf("%s: ожидалась ошибка", link)
		}
	}
}
