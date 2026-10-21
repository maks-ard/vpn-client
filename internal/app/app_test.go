package app

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maks-ard/vpn-client/internal/ovpn"
	"github.com/maks-ard/vpn-client/internal/singbox"
)

func testPaths(t *testing.T) Paths {
	dir := t.TempDir()
	return Paths{Config: filepath.Join(dir, "config"), Data: filepath.Join(dir, "data")}
}

func TestSettingsNormalize(t *testing.T) {
	s := Settings{Link: "  https://sub.example.com/x ", Server: "NL", CorpDomains: []string{" *.corp.example.com. ", "corp.example.com", ""}}
	if err := s.normalize(); err != nil {
		t.Fatal(err)
	}
	if s.Link != "https://sub.example.com/x" || len(s.CorpDomains) != 1 || s.CorpDomains[0] != "corp.example.com" {
		t.Errorf("normalize: %+v", s)
	}
	for _, bad := range []Settings{{Link: "ftp://x"}, {CorpDomains: []string{"not a domain"}}, {CorpDomains: []string{"localhost"}}} {
		if err := bad.normalize(); err == nil {
			t.Errorf("ожидалась ошибка для %+v", bad)
		}
	}
}

func TestImportOVPNInlinesFiles(t *testing.T) {
	src := t.TempDir()
	ca, _ := os.ReadFile("../singbox/testdata/corp.ovpn")
	full, err := ovpn.Parse(strings.NewReader(string(ca)), "")
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(src, "ca.crt"), []byte(full.CA), 0o600)
	_ = os.WriteFile(filepath.Join(src, "client.crt"), []byte(full.Cert), 0o600)
	_ = os.WriteFile(filepath.Join(src, "client.key"), []byte(full.Key), 0o600)
	_ = os.WriteFile(filepath.Join(src, "ta.key"), []byte(full.TLSAuth), 0o600)
	_ = os.WriteFile(filepath.Join(src, "pass.txt"), []byte("user\npw\n"), 0o600)
	_ = os.WriteFile(filepath.Join(src, "work.ovpn"), []byte("client\ndev tun\nremote vpn.example.com 1194\nca ca.crt\ncert client.crt\nkey client.key\ntls-auth ta.key 1\nauth-user-pass pass.txt\n"), 0o600)

	p := testPaths(t)
	name, data, err := PrepareOVPN(filepath.Join(src, "work.ovpn"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := importOVPN(p, name, data)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Loaded || info.Name != "work.ovpn" || info.Server != "vpn.example.com:1194 · udp" || info.NeedsAuth {
		t.Errorf("info = %+v", info)
	}
	// Исходные файлы больше не нужны: копия самодостаточна.
	_ = os.RemoveAll(src)
	saved, err := ovpn.ParseFile(p.ovpnFile())
	if err != nil {
		t.Fatal(err)
	}
	if saved.CA != full.CA || saved.Key != full.Key || saved.KeyDirection != "client" || saved.Username != "user" {
		t.Errorf("сохранённая копия неполная: %+v", saved)
	}
}

func TestSettingsProfile(t *testing.T) {
	p := testPaths(t)
	if _, err := (Settings{}).profile(p); err == nil || !strings.Contains(err.Error(), "подписку") {
		t.Errorf("пустые настройки: %v", err)
	}
	prof, err := (Settings{Link: "https://x.example/sub", Server: "NL", RussiaDirect: false}).profile(p)
	if err != nil {
		t.Fatal(err)
	}
	if prof.Subscription == nil || prof.Subscription.Server != "NL" || prof.RussiaDirect() || prof.OpenVPN != nil {
		t.Errorf("profile = %+v", prof)
	}
}

// TestManagerWithSingBox поднимает настоящий sing-box (вместо TUN — локальный
// mixed inbound) и проверяет полный цикл подключения.
func TestManagerWithSingBox(t *testing.T) {
	exe := os.Getenv("VPNCLIENT_SINGBOX")
	if exe == "" {
		t.Skip("VPNCLIENT_SINGBOX не задан")
	}
	links := "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:9?security=tls&sni=a.example.com#NL\n" +
		"vless://11111111-2222-3333-4444-555555555555@127.0.0.1:10?security=tls&sni=b.example.com#DE\n"
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=1; download=2; total=10")
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(links))))
	}))
	defer sub.Close()

	var mu sync.Mutex
	var states []Status
	m, err := NewManager(testPaths(t), func(s State) {
		mu.Lock()
		if len(states) == 0 || states[len(states)-1] != s.Status {
			states = append(states, s.Status)
		}
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	m.singBoxPath = exe
	m.inbound = singbox.M{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
	if err := m.SaveSettings(Settings{Link: sub.URL, RussiaDirect: false}); err != nil {
		t.Fatal(err)
	}

	m.Connect()
	deadline := time.Now().Add(20 * time.Second)
	for m.State().Status != StatusConnected {
		if st := m.State(); st.Status == StatusError || time.Now().After(deadline) {
			t.Fatalf("не подключилось: %+v", st)
		}
		time.Sleep(100 * time.Millisecond)
	}
	st := m.State()
	if len(st.Proxy.Servers) != 2 || st.Proxy.Total != 10 || st.Proxy.Used != 3 {
		t.Errorf("proxy state: %+v", st.Proxy)
	}
	if err := m.SelectServer("DE"); err != nil {
		t.Fatalf("выбор сервера: %v", err)
	}
	if st := m.State(); st.Proxy.Selected != "DE" || st.Proxy.Current != "DE" {
		t.Errorf("после выбора: selected=%q current=%q", st.Proxy.Selected, st.Proxy.Current)
	}
	if m.Settings().Server != "DE" {
		t.Error("выбор сервера не сохранён в настройках")
	}

	m.Disconnect()
	if st := m.State(); st.Status != StatusDisconnected {
		t.Fatalf("после отключения: %+v", st)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []Status{StatusDisconnected, StatusConnecting, StatusConnected, StatusDisconnected}
	if strings.Join(statusStrings(states), ",") != strings.Join(statusStrings(want), ",") {
		t.Errorf("переходы состояний: %v", states)
	}
	if log, _ := os.ReadFile(m.LogFile()); !strings.Contains(string(log), "подключено") {
		t.Errorf("журнал не записан: %s", log)
	}
}

func statusStrings(s []Status) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = string(v)
	}
	return out
}

func TestLogRedactsSubscription(t *testing.T) {
	p := testPaths(t)
	m, err := NewManager(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	link := "https://sub.example.com/secret-token-123"
	if err := m.SaveSettings(Settings{Link: link}); err != nil {
		t.Fatal(err)
	}
	m.Logf("ошибка подписки: Get %q: timeout", link)
	data, err := m.Log(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-token") || !strings.Contains(string(data), "***") {
		t.Errorf("ссылка попала в журнал: %s", data)
	}
}
