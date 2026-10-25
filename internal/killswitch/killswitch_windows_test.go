package killswitch

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Размеры и смещения из fwpmtypes.h для 64-битной Windows: ошибка в
// раскладке не ловится компилятором и ломает вызовы WFP.
func TestLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("раскладка проверяется для 64-битной сборки")
	}
	var f fwpmFilter0
	var c fwpmFilterCondition0
	var s fwpmSession0
	var l fwpmSublayer0
	checks := []struct {
		name      string
		got, want uintptr
	}{
		{"FWPM_FILTER0", unsafe.Sizeof(f), 200},
		{"FWPM_FILTER0.weight", unsafe.Offsetof(f.weight), 96},
		{"FWPM_FILTER0.numFilterConditions", unsafe.Offsetof(f.numFilterConditions), 112},
		{"FWPM_FILTER0.filterCondition", unsafe.Offsetof(f.filterCondition), 120},
		{"FWPM_FILTER0.action", unsafe.Offsetof(f.action), 128},
		{"FWPM_FILTER0.providerContextKey", unsafe.Offsetof(f.providerContextKey), 152},
		{"FWPM_FILTER0.filterID", unsafe.Offsetof(f.filterID), 176},
		{"FWPM_FILTER0.effectiveWeight", unsafe.Offsetof(f.effectiveWeight), 184},
		{"FWPM_FILTER_CONDITION0", unsafe.Sizeof(c), 40},
		{"FWPM_FILTER_CONDITION0.conditionValue", unsafe.Offsetof(c.value), 24},
		{"FWPM_SESSION0", unsafe.Sizeof(s), 72},
		{"FWPM_SESSION0.sid", unsafe.Offsetof(s.sid), 48},
		{"FWPM_SESSION0.kernelMode", unsafe.Offsetof(s.kernelMode), 64},
		{"FWPM_SUBLAYER0", unsafe.Sizeof(l), 72},
		{"FWPM_SUBLAYER0.weight", unsafe.Offsetof(l.weight), 64},
		{"FWP_VALUE0", unsafe.Sizeof(fwpValue0{}), 16},
		{"FWPM_ACTION0", unsafe.Sizeof(fwpmAction0{}), 20},
		{"FWP_V6_ADDR_AND_MASK", unsafe.Sizeof(fwpV6AddrAndMask{}), 17},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: %d, ожидалось %d", c.name, c.got, c.want)
		}
	}
}

func TestV4HostOrder(t *testing.T) {
	if got := v4(netip.MustParseAddr("172.19.0.1")); got != 0xac130001 {
		t.Fatalf("v4 = %#x", got)
	}
}

// TestEnable ставит настоящие фильтры: на пару секунд интернет пропадает у
// всего компьютера. Нужны права администратора и VPNCLIENT_KILLSWITCH_TEST=1.
func TestEnable(t *testing.T) {
	if os.Getenv("VPNCLIENT_KILLSWITCH_TEST") == "" {
		t.Skip("задайте VPNCLIENT_KILLSWITCH_TEST=1 и запустите от администратора")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("нужны права администратора")
	}
	const target = "1.1.1.1:443"
	// Адрес адаптера, через который цель доступна мимо TUN, и его интерфейс.
	var bypass netip.Addr
	var bypassIndex int
	// from — адрес адаптера; пустой — маршрут по умолчанию. Привязка к
	// интерфейсу через IP_UNICAST_IF, как у sing-box: с одной лишь привязкой
	// к адресу пакет всё равно уходит по маршруту через TUN.
	dial := func(from netip.Addr) error {
		d := net.Dialer{Timeout: 3 * time.Second}
		if from.IsValid() {
			index := bypassIndex
			d.Control = func(_, _ string, c syscall.RawConn) error {
				var serr error
				err := c.Control(func(fd uintptr) {
					var be [4]byte
					binary.BigEndian.PutUint32(be[:], uint32(index))
					serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(binary.LittleEndian.Uint32(be[:])))
				})
				return errors.Join(err, serr)
			}
		}
		c, err := d.Dial("tcp", target)
		if err == nil {
			_ = c.Close()
		}
		return err
	}
	if err := dial(netip.Addr{}); err != nil {
		t.Skipf("%s недоступен и без блокировки: %v", target, err)
	}

	// Локальный адрес маршрута до цели: при включённом VPN это адрес TUN.
	probe, err := net.Dial("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	route := probe.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	_ = probe.Close()
	// Так в сеть выходят sing-box и служба, когда VPN лежит.
	ifaces, _ := net.Interfaces()
search:
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil || !p.Addr().Is4() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() || p.Addr() == route {
				continue
			}
			bypass, bypassIndex = p.Addr(), iface.Index
			if dial(bypass) == nil {
				break search
			}
			bypass = netip.Addr{}
		}
	}
	t.Logf("адрес маршрута: %s, адрес напрямую: %s", route, bypass)

	fw, err := Enable(Rules{})
	if err != nil {
		t.Fatal(err)
	}
	defer fw.Close()
	self, _ := os.Executable()
	steps := []struct {
		name  string
		rules Rules
		from  netip.Addr
		allow bool
	}{
		{"ничего не разрешено", Rules{}, netip.Addr{}, false},
		{"ничего не разрешено, напрямую", Rules{}, bypass, false},
		{"разрешён адрес маршрута", Rules{Tunnel: []netip.Addr{route}}, netip.Addr{}, true},
		{"разрешён адрес маршрута, напрямую", Rules{Tunnel: []netip.Addr{route}}, bypass, route == bypass},
		{"разрешена программа, напрямую", Rules{Apps: []string{self}}, bypass, true},
		{"разрешена программа, через TUN", Rules{Apps: []string{self}, Tunnel: []netip.Addr{route}}, netip.Addr{}, true},
		{"разрешения сняты", Rules{}, netip.Addr{}, false},
	}
	for _, s := range steps {
		if s.from == (netip.Addr{}) && strings.HasSuffix(s.name, "напрямую") {
			t.Logf("%s: пропущено, нет второго адаптера", s.name)
			continue
		}
		if err := fw.Update(s.rules); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		// Номера фильтров сверяются с netsh wfp show netevents.
		t.Logf("%s: фильтры %v", s.name, fw.filters)
		err := dial(s.from)
		switch {
		case s.allow && err != nil:
			t.Errorf("%s: соединение заблокировано: %v", s.name, err)
		case !s.allow && err == nil:
			t.Errorf("%s: соединение прошло мимо kill switch", s.name)
		default:
			t.Logf("%s: %v", s.name, err)
		}
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dial(netip.Addr{}); err != nil {
		t.Fatalf("после Close сеть не вернулась: %v", err)
	}
}
