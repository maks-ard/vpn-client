package openvpn

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestConfig(t *testing.T) {
	ovpn := strings.Join([]string{
		"client",
		"dev tun",
		"remote vpn.example.com 1194",
		"redirect-gateway def1",
		"block-outside-dns",
		"dhcp-option DNS 8.8.8.8",
		"script-security 2",
		"up C:\\evil.bat",
		"plugin evil.dll",
		"management 127.0.0.1 7505",
		"log-append C:\\Windows\\evil.log",
		"ca C:\\Users\\me\\ca.crt",
		"tls-auth [inline] 1",
		"http-proxy proxy.local 3128 C:\\secret.txt",
		"<connection>",
		"remote vpn2.example.com 443 tcp",
		"status C:\\Windows\\evil.txt",
		"</connection>",
		"<ca>",
		"-----BEGIN CERTIFICATE-----",
		"up-in-a-block-is-data",
		"-----END CERTIFICATE-----",
		"</ca>",
		"auth-user-pass",
		"<auth-user-pass>",
		"old",
		"oldpass",
		"</auth-user-pass>",
		"verb 1",
	}, "\r\n")

	data, warnings, err := Config([]byte(ovpn), "alice", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	lines := strings.Split(strings.TrimSpace(got), "\n")

	for i, want := range header {
		if lines[i] != want {
			t.Errorf("строка %d = %q, ожидалась %q: правила службы должны идти первыми", i, lines[i], want)
		}
	}
	body := strings.Join(lines[len(header):], "\n") + "\n"
	for _, bad := range []string{"redirect-gateway", "block-outside-dns", "8.8.8.8", "script-security",
		"evil.bat", "evil.dll", "management", "evil.log", `C:\Users\me\ca.crt`, "secret.txt", "evil.txt", "old\n"} {
		if strings.Contains(body, bad) {
			t.Errorf("в конфиге осталось %q:\n%s", bad, got)
		}
	}
	for _, keep := range []string{"remote vpn.example.com 1194", "tls-auth [inline] 1", "<connection>",
		"remote vpn2.example.com 443 tcp", "up-in-a-block-is-data", "auth-user-pass\n"} {
		if !strings.Contains(got, keep) {
			t.Errorf("в конфиге нет %q:\n%s", keep, got)
		}
	}
	if !strings.HasSuffix(got, "verb 3\n<auth-user-pass>\nalice\ns3cret\n</auth-user-pass>\n") {
		t.Errorf("конец конфига:\n%s", got)
	}
	if strings.Contains(got, "\r") {
		t.Error("в конфиге остались \\r")
	}
	if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, "\n"), "script-security") {
		t.Errorf("нет замечаний о пропущенных директивах: %q", warnings)
	}
}

func TestConfigKeepsInlineAuthWithoutCredentials(t *testing.T) {
	data, _, err := Config([]byte("client\n<auth-user-pass>\nbob\npw\n</auth-user-pass>\n"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "<auth-user-pass>\nbob\npw\n</auth-user-pass>\n") {
		t.Errorf("встроенные в .ovpn логин и пароль потеряны:\n%s", data)
	}
}

func TestConfigErrors(t *testing.T) {
	for name, tc := range map[string]struct{ ovpn, user, pass string }{
		"перевод строки в пароле": {"client\n", "alice", "a\nb"},
		"незакрытый блок":         {"client\n<ca>\nxxx\n", "", ""},
	} {
		if _, _, err := Config([]byte(tc.ovpn), tc.user, tc.pass); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

// Журнал OpenVPN 2.6.19 со стенда: сервер присылает маршрут, DNS, домен и
// redirect-gateway, клиент запущен с конфигом из Config.
const sessionLog = `2026-10-27 15:04:44 OpenVPN 2.6.19 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
2026-10-27 15:04:44 TCP/UDP: Preserving recently used remote address: [AF_INET]172.31.250.2:1194
2026-10-27 15:04:44 UDPv4 link local: (not bound)
2026-10-27 15:04:44 UDPv4 link remote: [AF_INET]172.31.250.2:1194
2026-10-27 15:04:44 [server] Peer Connection Initiated with [AF_INET]172.31.250.2:1194
2026-10-27 15:04:44 PUSH: Received control message: 'PUSH_REPLY,route 10.99.0.0 255.255.0.0,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp.test,redirect-gateway def1,block-outside-dns,route-gateway 10.8.0.1,topology subnet,ifconfig 10.8.0.2 255.255.255.0,peer-id 0,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm dyn-tls-crypt,tun-mtu 1500'
2026-10-27 15:04:44 Pushed option removed by filter: 'dhcp-option DNS 10.8.0.1'
2026-10-27 15:04:44 TUN/TAP device tun0 opened
2026-10-27 15:04:44 net_route_v4_add: 0.0.0.0/0 via 10.8.0.1 dev [NULL] table 0 metric 9999
2026-10-27 15:04:44 Initialization Sequence Completed
`

func feed(w *Watcher, log string) []Event {
	var events []Event
	for _, line := range strings.Split(log, "\n") {
		if ev, ok := w.Feed(line); ok {
			events = append(events, ev)
		}
	}
	return events
}

func TestWatcher(t *testing.T) {
	var w Watcher
	events := feed(&w, sessionLog)
	if len(events) != 1 || events[0].Kind != EventUp {
		t.Fatalf("события: %+v", events)
	}
	want := &Link{
		Interface: "tun0",
		Server:    netip.MustParseAddr("172.31.250.2"),
		Local:     netip.MustParseAddr("10.8.0.2"),
		DNS:       []netip.Addr{netip.MustParseAddr("10.8.0.1")},
		Domains:   []string{"corp.test"},
		Routes:    []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
	}
	if got := events[0].Link; !got.Equal(want) {
		t.Errorf("link = %+v\nожидалось %+v", got, want)
	}

	// Переподключение: адаптер с persist-tun не открывается заново, имя
	// остаётся прежним, а настройки сервера берутся из нового ответа.
	events = feed(&w, `2026-10-27 15:10:00 [server] Inactivity timeout (--ping-restart), restarting
2026-10-27 15:10:00 SIGUSR1[soft,ping-restart] received, process restarting
2026-10-27 15:10:05 TCP connection established with [AF_INET]172.31.250.3:443
2026-10-27 15:10:05 PUSH: Received control message: 'PUSH_REPLY,route 10.98.0.0 255.255.0.0,dns server 0 address 10.8.0.53 [fd00::53]:53 10.8.0.54:5353,dns search-domains Corp.Test. other.test,push-continuation 2'
2026-10-27 15:10:05 PUSH: Received control message: 'PUSH_REPLY,route-ipv6 fd00:99::/64,route 192.0.2.10 255.255.255.255 net_gateway,ifconfig 10.8.0.6 10.8.0.5,push-continuation 1'
2026-10-27 15:10:05 Initialization Sequence Completed`)
	if len(events) != 2 || events[0].Kind != EventDown || events[1].Kind != EventUp {
		t.Fatalf("события: %+v", events)
	}
	want = &Link{
		Interface: "tun0",
		Server:    netip.MustParseAddr("172.31.250.3"),
		Local:     netip.MustParseAddr("10.8.0.6"),
		DNS:       []netip.Addr{netip.MustParseAddr("10.8.0.53"), netip.MustParseAddr("fd00::53")},
		Domains:   []string{"corp.test", "other.test"},
		Routes:    []netip.Prefix{netip.MustParsePrefix("10.98.0.0/16"), netip.MustParsePrefix("fd00:99::/64")},
	}
	if got := events[1].Link; !got.Equal(want) {
		t.Errorf("link после переподключения = %+v\nожидалось %+v", got, want)
	}

	events = feed(&w, `2026-10-27 15:20:00 AUTH: Received control message: AUTH_FAILED
2026-10-27 15:20:00 SIGTERM[soft,auth-failure] received, process exiting`)
	if len(events) != 1 || events[0].Kind != EventAuthFailed {
		t.Errorf("события при отказе авторизации: %+v", events)
	}
}

func TestDeviceName(t *testing.T) {
	for line, want := range map[string]string{
		"2026-10-27 15:04:44 ovpn-dco device [OpenVPN Data Channel Offload] opened": "OpenVPN Data Channel Offload",
		"Tue Oct 27 15:04:44 2026 wintun device [OpenVPN Wintun] opened":            "OpenVPN Wintun",
		"2026-10-27 15:04:44 DCO device tun0 opened":                                "tun0",
		"2026-10-27 15:04:44 TUN/TAP device tun1 opened":                            "tun1",
		"2026-10-27 15:04:44 net_iface_up: set tun0 up":                             "",
	} {
		got, ok := deviceName(line)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q, %v", line, got, ok)
		}
	}
}

func TestMaskBits(t *testing.T) {
	for mask, want := range map[string]int{
		"255.255.255.255": 32, "255.255.0.0": 16, "0.0.0.0": 0, "255.0.255.0": -1, "24": 24, "x": -1,
	} {
		if got := maskBits(mask); got != want {
			t.Errorf("maskBits(%q) = %d, ожидалось %d", mask, got, want)
		}
	}
}

func TestLinkEqual(t *testing.T) {
	a := &Link{Interface: "tun0", Routes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	b := &Link{Interface: "tun0", Routes: slices.Clone(a.Routes)}
	if !a.Equal(b) || a.Equal(nil) || !(*Link)(nil).Equal(nil) {
		t.Error("Equal работает неверно")
	}
	b.Routes = nil
	if a.Equal(b) {
		t.Error("разные маршруты считаются одинаковыми")
	}
}
