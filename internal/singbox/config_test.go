package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/maks-ard/vpn-client/internal/profile"
	"github.com/maks-ard/vpn-client/internal/subscription"
	"github.com/maks-ard/vpn-client/internal/vless"
)

func loadTestConfig(t *testing.T) M {
	t.Helper()
	in, err := Load(context.Background(), "testdata/profile.yaml", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	var cfg M
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// routeOf возвращает outbound первого правила, содержащего key со значением value.
func routeOf(rules []any, key, value string) string {
	for _, r := range rules {
		rule := r.(M)
		switch v := rule[key].(type) {
		case string:
			if v == value {
				return rule["outbound"].(string)
			}
		case []any:
			for _, item := range v {
				if item == value {
					return rule["outbound"].(string)
				}
			}
		}
	}
	return ""
}

func TestBuildRouting(t *testing.T) {
	cfg := loadTestConfig(t)
	route := cfg["route"].(M)
	rules := route["rules"].([]any)

	if route["final"] != TagProxy {
		t.Errorf("final = %v, ожидался proxy", route["final"])
	}
	checks := []struct{ key, value, want string }{
		{"domain_suffix", "corp.example.com", TagCorp},
		{"preferred_by", TagCorp, TagCorp},
		{"ip_cidr", "10.10.0.0/16", TagCorp},
		{"domain_suffix", "example.ru", TagProxy},
		{"domain_suffix", "example.com", TagDirect},
		{"domain_suffix", "ru", TagDirect},
		{"rule_set", "geoip-ru", TagDirect},
		{"process_name", "qbittorrent.exe", TagDirect},
	}
	for _, c := range checks {
		if got := routeOf(rules, c.key, c.value); got != c.want {
			t.Errorf("%s=%s → %q, ожидался %q", c.key, c.value, got, c.want)
		}
	}

	// Порядок важен: корпоративное раньше приватных сетей, proxy_domains раньше .ru.
	index := func(key, value string) int {
		for i, r := range rules {
			if b, _ := json.Marshal(r.(M)[key]); strings.Contains(string(b), `"`+value+`"`) {
				return i
			}
		}
		return -1
	}
	privateIdx := -1
	for i, r := range rules {
		if _, ok := r.(M)["ip_is_private"]; ok {
			privateIdx = i
		}
	}
	if privateIdx < index("ip_cidr", "10.10.0.0/16") {
		t.Error("правило приватных сетей стоит раньше корпоративных подсетей")
	}
	if index("domain_suffix", "example.ru") > index("domain_suffix", "ru") {
		t.Error("proxy_domains должны проверяться раньше российских доменов")
	}
}

func TestBuildOpenVPN(t *testing.T) {
	cfg := loadTestConfig(t)
	ep := cfg["endpoints"].([]any)[0].(M)
	if ep["type"] != "openvpn-client" || ep["tag"] != TagCorp {
		t.Fatalf("endpoint: %v", ep)
	}
	if ep["username"] != "user" || ep["password"] != "secret" {
		t.Errorf("логин/пароль из профиля не подставлены")
	}
	servers := ep["servers"].([]any)
	if len(servers) != 2 || servers[1].(M)["network"] != "tcp" || servers[1].(M)["server_port"] != 443.0 {
		t.Errorf("servers = %v", servers)
	}
	filters := ep["pull_filters"].([]any)
	if filters[0].(M)["text"] != "redirect-gateway" || filters[0].(M)["action"] != "ignore" {
		t.Errorf("redirect-gateway от сервера должен игнорироваться: %v", filters)
	}
	tls := ep["tls"].(M)
	if tls["server_name"] != "vpn server" || tls["server_name_type"] != "name" || tls["remote_certificate_tls"] != "server" {
		t.Errorf("tls = %v", tls)
	}
	if wrap := tls["control_wrap"].(M); wrap["type"] != "tls_auth" || wrap["direction"] != "client" {
		t.Errorf("control_wrap = %v", wrap)
	}
	if ep["data_ciphers_fallback"] != "AES-256-CBC" || ep["auth"] != "SHA256" {
		t.Errorf("ciphers: %v %v", ep["data_ciphers_fallback"], ep["auth"])
	}
}

func TestBuildDNS(t *testing.T) {
	cfg := loadTestConfig(t)
	dns := cfg["dns"].(M)
	if dns["final"] != TagDNSRemote || dns["strategy"] != "ipv4_only" {
		t.Errorf("dns final/strategy = %v/%v", dns["final"], dns["strategy"])
	}
	rules := dns["rules"].([]any)
	first := rules[0].(M)
	if first["server"] != TagDNSCorp {
		t.Errorf("первым должно идти правило корпоративного DNS: %v", first)
	}
	var remote M
	for _, s := range dns["servers"].([]any) {
		if s.(M)["tag"] == TagDNSRemote {
			remote = s.(M)
		}
	}
	if remote["detour"] != TagProxy || remote["server"] != "1.1.1.1" {
		t.Errorf("удалённый DNS должен идти через VLESS: %v", remote)
	}
}

func TestBuildWithoutVLESS(t *testing.T) {
	p, err := profile.Parse([]byte("openvpn:\n  config: corp.ovpn\n  username: u\n  password: p\ncorporate:\n  domains: [corp.example.com]\n"), "testdata")
	if err != nil {
		t.Fatal(err)
	}
	in := &Input{Profile: p}
	if in.OpenVPN, err = loadOVPN(p); err != nil {
		t.Fatal(err)
	}
	data, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	var cfg M
	_ = json.Unmarshal(data, &cfg)
	if cfg["route"].(M)["final"] != TagDirect {
		t.Error("без VLESS весь остальной трафик должен идти напрямую")
	}
	if _, ok := cfg["route"].(M)["rule_set"]; ok {
		t.Error("без VLESS rule-set'ы не нужны")
	}
	if strings.Contains(string(data), `"proxy"`) {
		t.Error("в конфиге остались ссылки на proxy")
	}
}

func TestEarlyData(t *testing.T) {
	path, ed := splitEarlyData("/ws?ed=2048")
	if path != "/ws" || ed != 2048 {
		t.Errorf("got %q %d", path, ed)
	}
	path, ed = splitEarlyData("/ws?a=1&ed=x")
	if path != "/ws?a=1&ed=x" || ed != 0 {
		t.Errorf("got %q %d", path, ed)
	}
}

// TestSingBoxCheck прогоняет конфиг через настоящий sing-box, если он доступен:
// VPNCLIENT_SINGBOX=/path/to/sing-box go test ./...
func TestSingBoxCheck(t *testing.T) {
	exe := os.Getenv("VPNCLIENT_SINGBOX")
	if exe == "" {
		t.Skip("VPNCLIENT_SINGBOX не задан")
	}
	in, err := Load(context.Background(), "testdata/profile.yaml", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	singBoxCheck(t, exe, data)
	// Второй корпоративный суффикс должен сохраняться и в маршрутах, и в DNS.
	in.Profile.Corporate.Domains = []string{"corp.example", "office.local"}
	data, err = Build(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range in.Profile.Corporate.Domains {
		if strings.Count(string(data), domain) < 2 {
			t.Fatalf("домен %s не добавлен в маршруты и DNS", domain)
		}
	}
	singBoxCheck(t, exe, data)

	// Подписка с несколькими серверами: selector + urltest.
	sub, err := subscription.Parse([]byte("vless://id1@a.example.com:443?security=reality&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sni=a.com#A\nvless://id2@b.example.com:443?security=tls&type=grpc&serviceName=g#B"), nil)
	if err != nil {
		t.Fatal(err)
	}
	in.Servers, in.Subscription = sub.Servers, sub
	if data, err = Build(in); err != nil {
		t.Fatal(err)
	}
	singBoxCheck(t, exe, data)

	// Hysteria2 со сменой портов и обфускацией рядом с VLESS.
	sub, err = subscription.Parse([]byte("vless://id1@a.example.com:443?security=tls#A\nhysteria2://pass@h.example.com:443,20000-30000?obfs=salamander&obfs-password=x&insecure=1#H"), nil)
	if err != nil {
		t.Fatal(err)
	}
	in.Servers, in.Subscription = sub.Servers, sub
	if data, err = Build(in); err != nil {
		t.Fatal(err)
	}
	singBoxCheck(t, exe, data)

	// Серверы с несколькими транспортами: вложенные urltest.
	in.Servers = variantServers()
	if data, err = Build(in); err != nil {
		t.Fatal(err)
	}
	singBoxCheck(t, exe, data)
	in.Servers = in.Servers[:1]
	if data, err = Build(in); err != nil {
		t.Fatal(err)
	}
	singBoxCheck(t, exe, data)
}

func singBoxCheck(t *testing.T, exe string, config []byte) {
	t.Helper()
	cmd := exec.Command(exe, "check", "-c", "stdin", "-D", t.TempDir())
	cmd.Stdin = strings.NewReader(string(config))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sing-box check: %v\n%s", err, out)
	}
}

func TestBuildSubscription(t *testing.T) {
	sub, err := subscription.Parse([]byte(strings.Join([]string{
		"vless://id1@nl.example.com:443?security=reality&pbk=K&sni=a.com#NL",
		"vless://id2@de.example.com:443?security=tls&type=ws&path=/ws#DE",
		"vless://id3@de2.example.com:443?security=tls#DE",
		"vless://id4@x.example.com:443?security=tls#auto",
	}, "\n")), nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := profile.Parse([]byte("subscription:\n  url: https://example.com/sub\n  server: DE\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := Build(&Input{Profile: p, Servers: sub.Servers, Subscription: sub})
	if err != nil {
		t.Fatal(err)
	}
	var cfg M
	_ = json.Unmarshal(data, &cfg)
	byTag := map[string]M{}
	for _, o := range cfg["outbounds"].([]any) {
		byTag[o.(M)["tag"].(string)] = o.(M)
	}
	for _, tag := range []string{"NL", "DE", "DE (2)", "auto ", TagAuto, TagProxy} {
		if byTag[tag] == nil {
			t.Errorf("нет outbound %q, есть: %v", tag, keys(byTag))
		}
	}
	if sel := byTag[TagProxy]; sel["type"] != "selector" || sel["default"] != "DE" {
		t.Errorf("selector = %v", sel)
	}
	if auto := byTag[TagAuto]; auto["type"] != "urltest" || len(auto["outbounds"].([]any)) != 4 {
		t.Errorf("urltest = %v", auto)
	}
}

// variantServers — два сервера, у первого два транспорта, как в подписках
// Remnawave; у второго имя совпадает с тегом варианта первого.
func variantServers() []subscription.Server {
	parse := func(raw string) *vless.Link {
		l, err := vless.Parse(raw)
		if err != nil {
			panic(err)
		}
		return l
	}
	return []subscription.Server{
		{Name: "NL", Links: []*vless.Link{
			parse("vless://id1@nl.example.com:443?security=reality&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sni=a.com#nl-rl"),
			parse("vless://id1@nl.example.com:80?type=ws&path=/ws#nl-ws"),
		}},
		{Name: "NL / nl-ws", Links: []*vless.Link{parse("vless://id2@de.example.com:443?security=tls#de")}},
	}
}

func TestBuildServerVariants(t *testing.T) {
	p, err := profile.Parse([]byte("subscription:\n  url: https://example.com/sub\n  server: NL\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := Build(&Input{Profile: p, Servers: variantServers()})
	if err != nil {
		t.Fatal(err)
	}
	var cfg M
	_ = json.Unmarshal(data, &cfg)
	byTag := map[string]M{}
	for _, o := range cfg["outbounds"].([]any) {
		byTag[o.(M)["tag"].(string)] = o.(M)
	}
	if nl := byTag["NL"]; nl["type"] != "urltest" || fmt.Sprint(nl["outbounds"]) != "[NL / nl-rl NL / nl-ws ]" {
		t.Errorf("NL = %v, есть: %v", nl, keys(byTag))
	}
	if byTag["NL / nl-ws"]["type"] != "vless" || byTag["NL / nl-ws "]["type"] != "vless" {
		t.Errorf("теги вариантов и сервера пересеклись: %v", keys(byTag))
	}
	if sel := byTag[TagProxy]; sel["default"] != "NL" || fmt.Sprint(sel["outbounds"]) != "[auto NL NL / nl-ws]" {
		t.Errorf("selector = %v", sel)
	}

	// Один сервер с вариантами — сам становится proxy.
	data, err = Build(&Input{Profile: p, Servers: variantServers()[:1]})
	if err != nil {
		t.Fatal(err)
	}
	cfg = nil
	_ = json.Unmarshal(data, &cfg)
	byTag = map[string]M{}
	for _, o := range cfg["outbounds"].([]any) {
		byTag[o.(M)["tag"].(string)] = o.(M)
	}
	if px := byTag[TagProxy]; px["type"] != "urltest" || byTag[TagAuto] != nil || byTag["proxy / nl-rl"] == nil {
		t.Errorf("один сервер: %v", keys(byTag))
	}
}

func TestBuildHysteria2(t *testing.T) {
	sub, err := subscription.Parse([]byte("hysteria2://user:pw@h.example.com:443,20000-30000/?sni=cdn.example.com&obfs=salamander&obfs-password=x#H"), nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := profile.Parse([]byte("subscription:\n  url: https://example.com/sub\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := Build(&Input{Profile: p, Servers: sub.Servers, Subscription: sub})
	if err != nil {
		t.Fatal(err)
	}
	var cfg M
	_ = json.Unmarshal(data, &cfg)
	var hy M
	for _, o := range cfg["outbounds"].([]any) {
		if o.(M)["tag"] == TagProxy {
			hy = o.(M)
		}
	}
	want := `map[obfs:map[password:x type:salamander] password:user:pw server:h.example.com server_port:443 server_ports:[443:443 20000:30000] tag:proxy tls:map[enabled:true server_name:cdn.example.com] type:hysteria2]`
	if got := fmt.Sprint(hy); got != want {
		t.Errorf("outbound:\n got %s\nwant %s", got, want)
	}
}

func keys(m map[string]M) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Пропущенные серверы подписки не должны постоянно висеть замечанием в окне:
// о них говорим, только если пропущен выбранный пользователем сервер.
func TestWarningsSkippedServers(t *testing.T) {
	sub := &subscription.Subscription{
		Servers: []subscription.Server{{Name: "Нидерланды"}},
		Skipped: []string{"Финляндия: транспорт XHTTP не поддерживается sing-box"},
	}
	for selected, want := range map[string]bool{"": false, "Нидерланды": false, "Финляндия": true, "Германия": false} {
		in := &Input{
			Profile:      &profile.Profile{Subscription: &profile.Subscription{Server: selected}},
			Subscription: sub,
			Servers:      sub.Servers,
		}
		warn := strings.Join(in.Warnings(), "\n")
		if got := strings.Contains(warn, "XHTTP"); got != want {
			t.Errorf("выбран %q: замечание %q", selected, warn)
		}
		if len(in.Skipped()) != 1 {
			t.Errorf("выбран %q: для журнала нужен полный список пропусков", selected)
		}
	}
}
