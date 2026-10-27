package app

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maks-ard/vpn-client/internal/openvpn"
	"github.com/maks-ard/vpn-client/internal/ovpn"
	"github.com/maks-ard/vpn-client/internal/singbox"
)

func TestSystemVPNCorpLink(t *testing.T) {
	s := &systemVPN{servers: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}
	offline := s.corpLink(nil)
	if offline.Interface != "" || len(offline.Servers) != 1 {
		t.Errorf("без подключения: %+v", offline)
	}
	link := &openvpn.Link{
		Interface: "tun0", Server: netip.MustParseAddr("203.0.113.2"), Local: netip.MustParseAddr("10.8.0.2"),
		DNS: []netip.Addr{netip.MustParseAddr("10.8.0.1")}, Domains: []string{"corp.test"},
		Routes: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
	}
	got := s.corpLink(link)
	if got.Interface != "tun0" || len(got.DNS) != 1 || len(got.Domains) != 1 || len(got.Routes) != 1 {
		t.Errorf("подключение: %+v", got)
	}
	// Сервер, к которому подключились, тоже мимо TUN, даже если его нет в .ovpn.
	if len(got.Servers) != 2 || got.Servers[1] != link.Server {
		t.Errorf("серверы: %v", got.Servers)
	}
}

func TestResolveRemotes(t *testing.T) {
	cfg := &ovpn.Config{Remotes: []ovpn.Remote{{Host: "203.0.113.1"}, {Host: "203.0.113.1"}, {Host: "localhost"}}}
	got := resolveRemotes(context.Background(), cfg)
	if len(got) < 2 || got[0] != netip.MustParseAddr("203.0.113.1") || got[1] != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("адреса серверов: %v", got)
	}
}

func TestSystemOpenVPNSettings(t *testing.T) {
	p := testPaths(t)
	if err := os.MkdirAll(p.Config, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../singbox/testdata/corp.ovpn")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := importOVPN(p, "corp.ovpn", data); err != nil {
		t.Fatal(err)
	}
	// «Адрес компании в Windows» при системном OpenVPN не нужен: адаптер
	// создаёт сам OpenVPN, и маршруты службы через свой адаптер не ставятся.
	prof, err := Settings{CorpAdapter: true, SystemOpenVPN: true}.profile(p)
	if err != nil {
		t.Fatal(err)
	}
	if prof.OpenVPN.SystemInterface {
		t.Error("при системном OpenVPN адаптер sing-box включён")
	}
	if !routingChanged(Settings{}, Settings{SystemOpenVPN: true}) {
		t.Error("переключение системного OpenVPN не переподключает VPN")
	}
}

// TestManagerWithSystemOpenVPN проходит полный цикл с настоящими OpenVPN и
// sing-box на стенде scripts/openvpn-lab.sh (нужен root).
func TestManagerWithSystemOpenVPN(t *testing.T) {
	exe, lab := os.Getenv("VPNCLIENT_SINGBOX"), os.Getenv("VPNCLIENT_OPENVPN_LAB")
	if exe == "" || lab == "" {
		t.Skip("VPNCLIENT_SINGBOX или VPNCLIENT_OPENVPN_LAB не задан")
	}
	ovpnExe, err := openvpn.Find()
	if err != nil {
		t.Skip(err)
	}
	p := testPaths(t)
	data, err := os.ReadFile(filepath.Join(lab, "client.ovpn"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := importOVPN(p, "lab.ovpn", data); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.singBoxPath, m.openVPNPath = exe, ovpnExe
	t.Cleanup(func() { m.Disconnect(); _ = m.log.Close() })
	addr, err := freeLocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	_, portText, _ := net.SplitHostPort(addr)
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	m.inbound = singbox.M{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": port}
	if err := m.SaveSettings(Settings{SystemOpenVPN: true, OVPNUsername: "alice", OVPNPassword: "s3cret",
		CorpDomains: []string{"corp.test"}}); err != nil {
		t.Fatal(err)
	}

	m.Connect()
	deadline := time.Now().Add(40 * time.Second)
	for st := m.State(); st.Status != StatusConnected || !st.Corp.Up; st = m.State() {
		if st.Status == StatusError || time.Now().After(deadline) {
			log, _ := os.ReadFile(m.LogFile())
			t.Fatalf("не подключилось: %+v\n%s", st, log)
		}
		time.Sleep(200 * time.Millisecond)
	}

	proxy := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr})}}
	get := func(target, host string) string {
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := proxy.Do(req)
		if err != nil {
			return err.Error()
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return resp.Status + ": " + string(body)
		}
		return strings.TrimSpace(string(body))
	}
	// Подсеть, присланная сервером, и адрес вне неё, который узнаётся по
	// домену компании: sing-box отправляет его в адаптер OpenVPN.
	if got := get("http://10.99.0.1/", "intranet.corp.test"); got != "corp-ok" {
		t.Errorf("сайт в подсети компании: %q", got)
	}
	if got := get("http://203.0.113.10/", "public.corp.test"); got != "corp-ok" {
		t.Errorf("сайт компании вне присланных подсетей: %q", got)
	}
	if t.Failed() {
		log, _ := os.ReadFile(m.LogFile())
		t.Logf("журнал:\n%s", log)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m.mu.Lock()
	api := m.api
	m.mu.Unlock()
	if err := api.dnsQuery(ctx, "intranet.corp.test"); err != nil {
		t.Errorf("DNS компании: %v", err)
	}

	log, _ := os.ReadFile(m.LogFile())
	for _, want := range []string{"Pushed option removed by filter: 'redirect-gateway def1'", "OpenVPN: подключено через"} {
		if !strings.Contains(string(log), want) {
			t.Errorf("в журнале нет %q", want)
		}
	}
	if strings.Contains(string(log), "s3cret") {
		t.Error("пароль OpenVPN попал в журнал")
	}
	iface := regexp.MustCompile(`OpenVPN: подключено через "([^"]+)"`).FindStringSubmatch(string(log))

	m.Disconnect()
	// OpenVPN остановлен корректно: адаптер и его маршруты убраны.
	if iface != nil {
		if _, err := net.InterfaceByName(iface[1]); err == nil {
			t.Errorf("адаптер %s остался после отключения", iface[1])
		}
	}
	if m.State().Status != StatusDisconnected {
		t.Errorf("после отключения: %+v", m.State())
	}
}

func TestSystemOpenVPNFallback(t *testing.T) {
	p := testPaths(t)
	data, err := os.ReadFile("../singbox/testdata/corp.ovpn")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := importOVPN(p, "corp.ovpn", data); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.log.Close() })
	// OpenVPN удалили: работает встроенный, подключение не ломается.
	m.openVPNPath = ""
	t.Setenv("PATH", "")
	t.Setenv("ProgramFiles", t.TempDir())
	sys, err := m.systemVPNFor(context.Background(), Settings{SystemOpenVPN: true})
	if sys != nil || err != nil {
		t.Fatalf("systemVPNFor = %v, %v", sys, err)
	}
}
