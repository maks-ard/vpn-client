package ovpn

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"

func TestParseInline(t *testing.T) {
	src := `client
dev tun
proto tcp-client
remote vpn.example.com 443
remote 203.0.113.1 1194 udp
remote-random
verify-x509-name "vpn server" name-prefix
remote-cert-tls server
data-ciphers AES-256-GCM:CHACHA20-POLY1305
keepalive 10 60
reneg-sec 0
mssfix 0
route 10.1.0.0 255.255.0.0
route 192.168.5.7
pull-filter ignore "dhcp-option DNS"
key-direction 1
auth-user-pass
<ca>
` + pem + `</ca>
<tls-auth>
KEY
</tls-auth>
`
	c, err := Parse(strings.NewReader(src), "")
	if err != nil {
		t.Fatal(err)
	}
	want := []Remote{{Host: "vpn.example.com", Port: 443}, {Host: "203.0.113.1", Port: 1194, Proto: "udp"}}
	if !reflect.DeepEqual(c.Remotes, want) {
		t.Errorf("remotes = %+v", c.Remotes)
	}
	if c.Proto != "tcp" || !c.RemoteRandom {
		t.Errorf("proto = %q, random = %v", c.Proto, c.RemoteRandom)
	}
	if c.VerifyX509Name != "vpn server" || c.VerifyX509Type != "name-prefix" {
		t.Errorf("verify-x509-name = %q %q", c.VerifyX509Name, c.VerifyX509Type)
	}
	if c.CA != pem || c.TLSAuth != "KEY\n" || c.KeyDirection != "client" {
		t.Errorf("ca/tls-auth/key-direction разобраны неверно: %q %q %q", c.CA, c.TLSAuth, c.KeyDirection)
	}
	if c.PingInterval != 10 || c.PingRestart != 60 || !c.RenegDisabled || !c.MSSFixDisabled {
		t.Errorf("таймеры: %+v", c)
	}
	if len(c.Routes) != 2 || c.Routes[0].String() != "10.1.0.0/16" || c.Routes[1].String() != "192.168.5.7/32" {
		t.Errorf("routes = %v", c.Routes)
	}
	if len(c.PullFilters) != 1 || c.PullFilters[0].Text != "dhcp-option DNS" {
		t.Errorf("pull-filter = %+v", c.PullFilters)
	}
	if !c.AuthUserPass || c.Username != "" {
		t.Errorf("auth-user-pass: %v %q", c.AuthUserPass, c.Username)
	}
	if len(c.Warnings) != 0 {
		t.Errorf("лишние предупреждения: %v", c.Warnings)
	}
}

func TestParseFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ca.crt", pem)
	write("client.crt", "CERT")
	write("client.key", "KEY")
	write("ta.key", "TA")
	write("creds.txt", "user\r\npass word\r\n")
	write("corp.ovpn", `client
remote vpn.example.com
ca ca.crt
cert client.crt
key client.key
tls-auth ta.key 1
auth-user-pass creds.txt
some-new-option 1
`)
	c, err := ParseFile(filepath.Join(dir, "corp.ovpn"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Cert != "CERT" || c.Key != "KEY" || c.TLSAuth != "TA" || c.KeyDirection != "client" {
		t.Errorf("файлы прочитаны неверно: %+v", c)
	}
	if c.Username != "user" || c.Password != "pass word" {
		t.Errorf("credentials = %q %q", c.Username, c.Password)
	}
	if c.Remotes[0].Port != 0 || c.Port != 1194 || c.Proto != "udp" {
		t.Errorf("значения по умолчанию: %+v %d %s", c.Remotes, c.Port, c.Proto)
	}
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "some-new-option") {
		t.Errorf("warnings = %v", c.Warnings)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"нет remote":     "client\n<ca>\nX\n</ca>\nauth-user-pass\n",
		"dev tap":        "dev tap\nremote a\n",
		"pkcs12":         "remote a\npkcs12 x.p12\n",
		"нет CA":         "remote a\nauth-user-pass\n",
		"нет auth":       "remote a\n<ca>\nX\n</ca>\n",
		"незакрытый":     "remote a\n<ca>\nX\n",
		"кавычка":        "remote \"a\n",
		"плохая маска":   "remote a\nroute 10.0.0.0 255.0.255.0\n",
		"connection":     "<connection>\nremote a\n</connection>\n",
		"неверный порт":  "remote a 70000\n",
		"неверный proto": "remote a\nproto sctp\n",
	}
	for name, src := range cases {
		if _, err := Parse(strings.NewReader(src), ""); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

func TestSplitArgs(t *testing.T) {
	cases := map[string][]string{
		`remote a 1`:                  {"remote", "a", "1"},
		`verify-x509-name "a b" name`: {"verify-x509-name", "a b", "name"},
		`x 'a\b'`:                     {"x", `a\b`},
		`x a\ b`:                      {"x", "a b"},
		`x a # comment`:               {"x", "a"},
		`x "a#b"`:                     {"x", "a#b"},
	}
	for in, want := range cases {
		got, err := splitArgs(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("splitArgs(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
