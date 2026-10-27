package app

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maks-ard/vpn-client/internal/killswitch"
	"github.com/maks-ard/vpn-client/internal/singbox"
)

// fakeFirewall записывает, что менеджер делал с блокировкой.
type fakeFirewall struct {
	mu       sync.Mutex
	enabled  int
	updated  int
	closed   int
	last     killswitch.Rules
	failWith error
}

func (f *fakeFirewall) enable(r killswitch.Rules) (firewall, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return nil, f.failWith
	}
	f.enabled++
	f.last = r
	return f, nil
}

func (f *fakeFirewall) Update(r killswitch.Rules) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updated++
	f.last = r
	return nil
}

func (f *fakeFirewall) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

func (f *fakeFirewall) counts() (enabled, updated, closed int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enabled, f.updated, f.closed
}

func newGuardManager(t *testing.T, on bool) (*Manager, *fakeFirewall) {
	t.Helper()
	m, err := NewManager(testPaths(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.log.Close() })
	fw := &fakeFirewall{}
	m.newFirewall = fw.enable
	m.settings.KillSwitch = on
	return m, fw
}

func TestKillSwitchOffByDefault(t *testing.T) {
	m, fw := newGuardManager(t, false)
	if m.Settings().KillSwitch {
		t.Fatal("kill switch должен быть выключен в новой установке")
	}
	m.guard(`C:\data\sing-box.exe`)
	if e, _, _ := fw.counts(); e != 0 || m.State().KillSwitch {
		t.Fatalf("выключенный kill switch включил блокировку: enabled=%d", e)
	}
}

func TestKillSwitchLifecycle(t *testing.T) {
	m, fw := newGuardManager(t, true)
	m.guard(`C:\data\sing-box.exe`)
	if e, _, _ := fw.counts(); e != 1 || !m.State().KillSwitch {
		t.Fatalf("блокировка не включилась: enabled=%d state=%v", e, m.State().KillSwitch)
	}
	if !slices.Contains(fw.last.Apps, `C:\data\sing-box.exe`) || !slices.Contains(fw.last.Tunnel, singbox.TunAddress4.Addr()) {
		t.Errorf("правила: %+v", fw.last)
	}
	// Перезапуск sing-box после обрыва обновляет правила, не снимая блокировку.
	m.guard(`C:\data\sing-box.exe`)
	if e, u, c := fw.counts(); e != 1 || u != 1 || c != 0 {
		t.Fatalf("повторная сессия: enabled=%d updated=%d closed=%d", e, u, c)
	}

	// Переподключение после изменения настроек держит блокировку.
	m.guardMu.Lock()
	m.keepGuard = true
	m.guardMu.Unlock()
	if !m.unguard() {
		t.Fatal("блокировка снята во время переподключения")
	}
	m.guardMu.Lock()
	m.keepGuard = false
	m.guardMu.Unlock()

	if m.unguard() {
		t.Fatal("блокировка осталась после отключения")
	}
	if _, _, c := fw.counts(); c != 1 || m.State().KillSwitch {
		t.Fatalf("после отключения: closed=%d state=%v", c, m.State().KillSwitch)
	}
}

func TestKillSwitchToggleDuringSession(t *testing.T) {
	m, fw := newGuardManager(t, false)
	m.guard(`C:\data\sing-box.exe`)
	m.settings.KillSwitch = true
	m.refreshGuard()
	if e, _, _ := fw.counts(); e != 1 {
		t.Fatalf("включение в настройках не поставило блокировку: enabled=%d", e)
	}
	m.settings.KillSwitch = false
	m.refreshGuard()
	if _, _, c := fw.counts(); c != 1 || m.State().KillSwitch {
		t.Fatalf("выключение в настройках не сняло блокировку: closed=%d", c)
	}
}

func TestKillSwitchFailureWarns(t *testing.T) {
	m, fw := newGuardManager(t, true)
	fw.failWith = errors.New("kill switch: нет доступа к WFP")
	m.guard(`C:\data\sing-box.exe`)
	st := m.State()
	if st.KillSwitch || len(st.Warnings) != 1 || !strings.HasPrefix(st.Warnings[0], killSwitchWarning) {
		t.Fatalf("ошибка kill switch не показана: %+v", st)
	}
	fw.failWith = nil
	m.guard(`C:\data\sing-box.exe`)
	if st := m.State(); !st.KillSwitch || len(st.Warnings) != 0 {
		t.Fatalf("замечание не убрано после успешного включения: %+v", st)
	}
}

// TestKillSwitchWithSingBox проверяет блокировку на полном цикле: она
// включается при подключении, переживает переподключение из-за настроек и
// снимается при отключении.
func TestKillSwitchWithSingBox(t *testing.T) {
	exe := os.Getenv("VPNCLIENT_SINGBOX")
	if exe == "" {
		t.Skip("VPNCLIENT_SINGBOX не задан")
	}
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("vless://11111111-2222-3333-4444-555555555555@127.0.0.1:9?security=tls&sni=a.example.com#NL\n"))
	}))
	defer sub.Close()
	m, fw := newGuardManager(t, true)
	m.singBoxPath = exe
	t.Cleanup(m.Disconnect)
	m.inbound = singbox.M{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
	settings := Settings{Link: sub.URL, KillSwitch: true}
	if err := m.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	waitConnected := func() {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for m.State().Status != StatusConnected {
			if st := m.State(); st.Status == StatusError || time.Now().After(deadline) {
				t.Fatalf("не подключилось: %+v", st)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	m.Connect()
	waitConnected()
	if e, _, _ := fw.counts(); e != 1 || !m.State().KillSwitch || !slices.Contains(fw.last.Apps, exe) {
		t.Fatalf("после подключения: enabled=%d state=%v apps=%v", e, m.State().KillSwitch, fw.last.Apps)
	}

	// Любое изменение маршрутизации переподключает VPN; домены не требуют
	// скачивать наборы правил.
	settings.CorpDomains = []string{"corp.example.com"}
	if err := m.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	waitConnected()
	if e, u, c := fw.counts(); e != 1 || u < 1 || c != 0 {
		t.Fatalf("переподключение сняло блокировку: enabled=%d updated=%d closed=%d", e, u, c)
	}

	m.Disconnect()
	if _, _, c := fw.counts(); c != 1 || m.State().KillSwitch {
		t.Fatalf("после отключения: closed=%d state=%+v", c, m.State())
	}
}

func TestGuardSystemOpenVPN(t *testing.T) {
	m, fw := newGuardManager(t, true)
	m.guard("/data/sing-box")
	// Адрес компании появляется, когда OpenVPN подключился: правила
	// обновляются на лету, блокировка не снимается.
	local := netip.MustParseAddr("10.8.0.2")
	m.guardCorp("/ovpn/openvpn", local)
	fw.mu.Lock()
	last := fw.last
	fw.mu.Unlock()
	if !slices.Contains(last.Apps, "/ovpn/openvpn") || !slices.Contains(last.Tunnel, local) {
		t.Errorf("правила: %+v", last)
	}
	m.guardCorp("", netip.Addr{})
	fw.mu.Lock()
	last = fw.last
	fw.mu.Unlock()
	if slices.Contains(last.Apps, "/ovpn/openvpn") || slices.Contains(last.Tunnel, local) {
		t.Errorf("разрешения OpenVPN остались после его остановки: %+v", last)
	}
	if enabled, _, closed := fw.counts(); enabled != 1 || closed != 0 {
		t.Errorf("блокировка включалась %d раз, снималась %d", enabled, closed)
	}
}
