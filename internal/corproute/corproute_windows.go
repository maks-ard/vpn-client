package corproute

import (
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                     = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitializeIpForwardEntry = iphlpapi.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2    = iphlpapi.NewProc("CreateIpForwardEntry2")
)

// Ensure прокладывает через адаптер name маршрут по умолчанию и маршруты
// к адресам hosts (только IPv4), которых ещё нет. Возвращает, сколько
// маршрутов добавлено.
func Ensure(name string, hosts []netip.Addr) (int, error) {
	luid, err := adapterLUID(name)
	if err != nil {
		return 0, err
	}
	existing, err := routesOn(luid)
	if err != nil {
		return 0, err
	}
	type route struct {
		prefix netip.Prefix
		metric uint32
	}
	want := []route{{netip.PrefixFrom(netip.IPv4Unspecified(), 0), defaultMetric}}
	for _, h := range hosts {
		if h.Is4() {
			want = append(want, route{netip.PrefixFrom(h, 32), 0})
		}
	}
	added := 0
	for _, r := range want {
		if existing[r.prefix] {
			continue
		}
		if err := createRoute(luid, r.prefix, r.metric); err != nil {
			if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
				continue
			}
			return added, fmt.Errorf("маршрут %s через %s: %w", r.prefix, name, err)
		}
		added++
	}
	return added, nil
}

// adapterLUID находит включённый адаптер с адресом IPv4 по имени.
func adapterLUID(name string) (uint64, error) {
	const flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(16 << 10)
	for {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("список адаптеров: %w", err)
		}
		for a := first; a != nil; a = a.Next {
			if windows.UTF16PtrToString(a.FriendlyName) == name &&
				a.OperStatus == windows.IfOperStatusUp && a.FirstUnicastAddress != nil {
				return a.Luid, nil
			}
		}
		return 0, ErrNoAdapter
	}
}

// routesOn возвращает маршруты IPv4, уже проложенные через адаптер luid.
func routesOn(luid uint64) (map[netip.Prefix]bool, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, fmt.Errorf("таблица маршрутов: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	routes := map[netip.Prefix]bool{}
	for _, row := range table.Rows() {
		if row.InterfaceLuid != luid || row.DestinationPrefix.Prefix.Family != windows.AF_INET {
			continue
		}
		sa := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.DestinationPrefix.Prefix))
		routes[netip.PrefixFrom(netip.AddrFrom4(sa.Addr), int(row.DestinationPrefix.PrefixLength))] = true
	}
	return routes, nil
}

// createRoute добавляет маршрут без шлюза: адаптер OpenVPN работает на
// уровне IP, пакеты в него отправляются напрямую.
func createRoute(luid uint64, prefix netip.Prefix, metric uint32) error {
	var row windows.MibIpForwardRow2
	// Заполняет время жизни и прочие поля значениями по умолчанию.
	_, _, _ = procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceLuid = luid
	dst := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.DestinationPrefix.Prefix))
	dst.Family = windows.AF_INET
	dst.Addr = prefix.Addr().As4()
	row.DestinationPrefix.PrefixLength = uint8(prefix.Bits())
	next := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.NextHop))
	next.Family = windows.AF_INET
	row.Metric = metric
	row.Protocol = windows.MIB_IPPROTO_NETMGMT
	row.Origin = windows.NlroManual
	r, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if r != 0 {
		return windows.Errno(r)
	}
	return nil
}
