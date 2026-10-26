package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/maks-ard/vpn-client/internal/corproute"
	"github.com/maks-ard/vpn-client/internal/singbox"
)

func corpConn(ip string, chains ...string) clashConnection {
	var c clashConnection
	c.Metadata.DestinationIP = ip
	c.Chains = chains
	return c
}

func TestLearnCorpHosts(t *testing.T) {
	known := netip.MustParseAddr("10.1.0.1")
	hosts, changed := learnCorpHosts([]netip.Addr{known}, []clashConnection{
		corpConn("10.20.0.5", singbox.TagCorp),
		corpConn("10.20.0.5", singbox.TagCorp),      // повтор
		corpConn("10.1.0.1", singbox.TagCorp),       // уже известен
		corpConn("192.168.1.10", singbox.TagDirect), // не OpenVPN
		corpConn("93.184.216.34", singbox.TagCorp),  // публичный
		corpConn("fd00::1", singbox.TagCorp),        // IPv6
		corpConn("", singbox.TagCorp),               // соединение по домену
		corpConn("172.20.1.1", "vless-1", singbox.TagProxy),
	})
	want := []netip.Addr{known, netip.MustParseAddr("10.20.0.5")}
	if !changed || !slices.Equal(hosts, want) {
		t.Fatalf("hosts = %v (changed=%v), want %v", hosts, changed, want)
	}
	if _, changed := learnCorpHosts(hosts, []clashConnection{corpConn("10.20.0.5", singbox.TagCorp)}); changed {
		t.Error("известный адрес не должен менять список")
	}
}

func TestLearnCorpHostsLimit(t *testing.T) {
	var conns []clashConnection
	for i := range maxCorpHosts + 10 {
		conns = append(conns, corpConn(fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), singbox.TagCorp))
	}
	hosts, _ := learnCorpHosts(nil, conns)
	if len(hosts) != maxCorpHosts {
		t.Fatalf("len = %d, want %d", len(hosts), maxCorpHosts)
	}
	if hosts[len(hosts)-1] != netip.MustParseAddr(conns[len(conns)-1].Metadata.DestinationIP) {
		t.Error("при переполнении должны забываться самые старые адреса")
	}
}

// TestCorpRoutes: адреса из соединений OpenVPN получают маршруты, когда
// адаптер появился, и запоминаются для следующего подключения.
func TestCorpRoutes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"connections":[
			{"metadata":{"destinationIP":"10.20.0.5"},"chains":["corp"]},
			{"metadata":{"destinationIP":"1.1.1.1"},"chains":["corp"]}]}`))
	}))
	defer srv.Close()

	m, err := NewManager(testPaths(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.log.Close() })
	if err := saveCorpHosts(m.paths, []netip.Addr{netip.MustParseAddr("10.1.0.1")}); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	calls := 0
	var got []netip.Addr
	done := make(chan struct{})
	m.ensureRoutes = func(name string, hosts []netip.Addr) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if name != singbox.CorpInterfaceName {
			t.Errorf("name = %q", name)
		}
		if calls == 1 {
			return 0, corproute.ErrNoAdapter // OpenVPN ещё подключается
		}
		if got == nil {
			got = slices.Clone(hosts)
			close(done)
		}
		return len(hosts), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		m.corpRoutes(ctx, &clash{base: srv.URL, http: srv.Client()})
		close(finished)
	}()
	select {
	case <-done:
	case <-time.After(3 * corpRoutesInterval):
		t.Fatal("маршруты не проложены после появления адаптера")
	}
	cancel()
	<-finished

	want := []netip.Addr{netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("10.20.0.5")}
	if !slices.Equal(got, want) {
		t.Errorf("маршруты к %v, want %v", got, want)
	}
	if saved := loadCorpHosts(m.paths); !slices.Equal(saved, want) {
		t.Errorf("сохранено %v, want %v", saved, want)
	}
}

func TestCorpAdapterSetting(t *testing.T) {
	p := testPaths(t)
	data, err := os.ReadFile("../singbox/testdata/corp.ovpn")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := importOVPN(p, "corp.ovpn", data); err != nil {
		t.Fatal(err)
	}
	s := defaultSettings()
	s.OVPNUsername, s.OVPNPassword = "u", "p"
	s.CorpAdapter = true
	prof, err := s.profile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !prof.OpenVPN.SystemInterface {
		t.Error("CorpAdapter не попал в профиль")
	}
	old := s
	old.CorpAdapter = false
	if !routingChanged(old, s) {
		t.Error("переключение адаптера должно переподключать VPN")
	}
}
