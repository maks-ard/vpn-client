package killswitch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Веса фильтров внутри нашего подслоя: срабатывает фильтр с большим весом.
// DNS блокируется выше локальной сети, но ниже TUN и разрешённых программ.
const (
	weightApps     = 15
	weightLoopback = 14
	weightTunnel   = 13
	weightService  = 12 // DHCP и NDP: без них адаптер теряет адрес
	weightDNS      = 11
	weightLAN      = 10
	weightBlockAll = 0
)

// Firewall — включённый kill switch. Фильтры живут, пока открыта сессия WFP.
type Firewall struct {
	mu       sync.Mutex
	engine   uintptr
	sublayer windows.GUID
	filters  []uint64
}

// Enable блокирует исходящие соединения, кроме разрешённых rules.
func Enable(rules Rules) (*Firewall, error) {
	name, _ := windows.UTF16PtrFromString("vpn-client")
	// Динамическая сессия: при её закрытии или завершении службы Windows
	// удаляет все добавленные в ней фильтры.
	session := fwpmSession0{
		displayData:          fwpmDisplayData0{name: name},
		flags:                fwpmSessionFlagDynamic,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}
	var engine uintptr
	err := wfpCall(procEngineOpen, 0, rpcCAuthnWinNT, 0, uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(&engine)))
	runtime.KeepAlive(name)
	if err != nil {
		return nil, fmt.Errorf("kill switch: подключение к WFP: %w", err)
	}
	f := &Firewall{engine: engine}
	if f.sublayer, err = windows.GenerateGUID(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("kill switch: %w", err)
	}
	var ids []uint64
	err = f.transaction(func() error {
		sub := fwpmSublayer0{
			subLayerKey: f.sublayer,
			displayData: fwpmDisplayData0{name: name},
			// Наш подслой проверяется раньше остальных.
			weight: 0xffff,
		}
		err := wfpCall(procSubLayerAdd, f.engine, uintptr(unsafe.Pointer(&sub)), 0)
		runtime.KeepAlive(name)
		if err != nil {
			return fmt.Errorf("подслой: %w", err)
		}
		ids, err = f.install(rules)
		return err
	})
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("kill switch: %w", err)
	}
	f.filters = ids
	return f, nil
}

// Update заменяет разрешения одной транзакцией: блокировка не снимается ни
// на миг, а при ошибке остаются прежние фильтры.
func (f *Firewall) Update(rules Rules) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.engine == 0 {
		return errors.New("kill switch выключен")
	}
	var ids []uint64
	err := f.transaction(func() error {
		for _, id := range f.filters {
			if err := wfpCall(procFilterDeleteByID, f.engine, uintptr(id)); err != nil {
				return fmt.Errorf("удаление фильтра: %w", err)
			}
		}
		var err error
		ids, err = f.install(rules)
		return err
	})
	if err != nil {
		return fmt.Errorf("kill switch: %w", err)
	}
	f.filters = ids
	return nil
}

// Close снимает блокировку.
func (f *Firewall) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.engine == 0 {
		return nil
	}
	err := wfpCall(procEngineClose, f.engine)
	f.engine, f.filters = 0, nil
	if err != nil {
		return fmt.Errorf("kill switch: закрытие сессии WFP: %w", err)
	}
	return nil
}

func (f *Firewall) transaction(fn func() error) error {
	if err := wfpCall(procTransactionBegin, f.engine, 0); err != nil {
		return fmt.Errorf("начало транзакции: %w", err)
	}
	if err := fn(); err != nil {
		_ = wfpCall(procTransactionAbort, f.engine)
		return err
	}
	if err := wfpCall(procTransactionCommit, f.engine); err != nil {
		_ = wfpCall(procTransactionAbort, f.engine)
		return fmt.Errorf("применение фильтров: %w", err)
	}
	return nil
}

// install добавляет фильтры обоих протоколов и возвращает их номера.
func (f *Firewall) install(rules Rules) ([]uint64, error) {
	// WFP читает условия по указателям, которые Go не видит в uintptr:
	// всё, на что они ссылаются, держим в keep до конца добавления.
	var keep []any
	defer runtime.KeepAlive(&keep)

	var apps []fwpmFilterCondition0
	for _, path := range rules.Apps {
		blob, err := appID(path)
		if err != nil {
			return nil, fmt.Errorf("программа %s: %w", path, err)
		}
		defer freeWFP(unsafe.Pointer(blob))
		apps = append(apps, condition(condAppID, fwpMatchEqual, fwpByteBlobType, uintptr(unsafe.Pointer(blob))))
	}
	if len(apps) > 0 {
		sd, err := userDescriptor()
		if err != nil {
			return nil, fmt.Errorf("учётная запись службы: %w", err)
		}
		blob := &fwpByteBlob{size: sd.Length(), data: (*byte)(unsafe.Pointer(sd))}
		keep = append(keep, sd, blob)
		// Условия с одним полем объединяются через «или», с разными — через «и».
		apps = append(apps, condition(condUserID, fwpMatchEqual, fwpSecurityDescriptor, uintptr(unsafe.Pointer(blob))))
	}

	type filter struct {
		name   string
		layer  windows.GUID
		weight uint8
		action uint32
		conds  []fwpmFilterCondition0
	}
	var list []filter
	both := func(name string, weight uint8, action uint32, v4, v6 []fwpmFilterCondition0) {
		if v4 != nil {
			list = append(list, filter{name + " (IPv4)", layerConnectV4, weight, action, v4})
		}
		if v6 != nil {
			list = append(list, filter{name + " (IPv6)", layerConnectV6, weight, action, v6})
		}
	}

	if len(apps) > 0 {
		both("vpn-client: служба и sing-box", weightApps, fwpActionPermit, apps, apps)
	}
	// Антивирусы с проверкой трафика заново
	// открывают уже разрешённые соединения программ из ядра, и WFP видит их
	// как соединения System. Без этого фильтра блокировались бы соединения
	// sing-box с серверами VPN. Мимо VPN это не пропускает: соединение самой
	// программы проверяется раньше и блокируется до перехвата.
	kernelName := windows.StringToUTF16("System")
	kernel := &fwpByteBlob{size: uint32(len(kernelName) * 2), data: (*byte)(unsafe.Pointer(&kernelName[0]))}
	keep = append(keep, kernelName, kernel)
	kernelApp := []fwpmFilterCondition0{condition(condAppID, fwpMatchEqual, fwpByteBlobType, uintptr(unsafe.Pointer(kernel)))}
	both("vpn-client: соединения ядра", weightApps, fwpActionPermit, kernelApp, kernelApp)
	loopback := []fwpmFilterCondition0{condition(condFlags, fwpMatchFlagsAllSet, fwpUint32, fwpConditionIsLoopback)}
	both("vpn-client: loopback", weightLoopback, fwpActionPermit, loopback, loopback)

	var tun4, tun6 []fwpmFilterCondition0
	for _, a := range rules.Tunnel {
		if a.Is4() {
			tun4 = append(tun4, condition(condLocalAddress, fwpMatchEqual, fwpUint32, uintptr(v4(a))))
		} else {
			b := new([16]byte)
			*b = a.As16()
			keep = append(keep, b)
			tun6 = append(tun6, condition(condLocalAddress, fwpMatchEqual, fwpByteArray16, uintptr(unsafe.Pointer(b))))
		}
	}
	both("vpn-client: трафик через TUN", weightTunnel, fwpActionPermit, tun4, tun6)

	udp := condition(condProtocol, fwpMatchEqual, fwpUint8, ipprotoUDP)
	both("vpn-client: DHCP", weightService, fwpActionPermit,
		[]fwpmFilterCondition0{udp, condition(condLocalPort, fwpMatchEqual, fwpUint16, 68), condition(condRemotePort, fwpMatchEqual, fwpUint16, 67)},
		[]fwpmFilterCondition0{udp, condition(condLocalPort, fwpMatchEqual, fwpUint16, 546), condition(condRemotePort, fwpMatchEqual, fwpUint16, 547)})
	ndp := []fwpmFilterCondition0{condition(condProtocol, fwpMatchEqual, fwpUint8, ipprotoICMPv6)}
	for t := uintptr(133); t <= 137; t++ {
		ndp = append(ndp, condition(condICMPType, fwpMatchEqual, fwpUint16, t))
	}
	both("vpn-client: NDP", weightService, fwpActionPermit, nil, ndp)

	dns := []fwpmFilterCondition0{condition(condRemotePort, fwpMatchEqual, fwpUint16, 53)}
	both("vpn-client: DNS мимо VPN", weightDNS, fwpActionBlock, dns, dns)

	var lan4, lan6 []fwpmFilterCondition0
	for _, p := range LAN {
		if p.Addr().Is4() {
			m := &fwpV4AddrAndMask{addr: v4(p.Addr()), mask: ^uint32(0) << (32 - p.Bits())}
			keep = append(keep, m)
			lan4 = append(lan4, condition(condRemoteAddress, fwpMatchEqual, fwpV4AddrMask, uintptr(unsafe.Pointer(m))))
		} else {
			m := &fwpV6AddrAndMask{addr: p.Addr().As16(), prefixLength: uint8(p.Bits())}
			keep = append(keep, m)
			lan6 = append(lan6, condition(condRemoteAddress, fwpMatchEqual, fwpV6AddrMask, uintptr(unsafe.Pointer(m))))
		}
	}
	both("vpn-client: локальная сеть", weightLAN, fwpActionPermit, lan4, lan6)

	block := []fwpmFilterCondition0{}
	both("vpn-client: всё остальное", weightBlockAll, fwpActionBlock, block, block)

	ids := make([]uint64, 0, len(list))
	for _, flt := range list {
		id, err := f.addFilter(flt.name, flt.layer, flt.weight, flt.action, flt.conds)
		if err != nil {
			return nil, fmt.Errorf("фильтр %q: %w", flt.name, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (f *Firewall) addFilter(name string, layer windows.GUID, weight uint8, action uint32, conds []fwpmFilterCondition0) (uint64, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	flt := fwpmFilter0{
		displayData: fwpmDisplayData0{name: n},
		layerKey:    layer,
		subLayerKey: f.sublayer,
		weight:      fwpValue0{typ: fwpUint8, value: uintptr(weight)},
		action:      fwpmAction0{typ: action},
	}
	if len(conds) > 0 {
		flt.numFilterConditions = uint32(len(conds))
		flt.filterCondition = &conds[0]
	}
	var id uint64
	err = wfpCall(procFilterAdd, f.engine, uintptr(unsafe.Pointer(&flt)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(n)
	runtime.KeepAlive(conds)
	return id, err
}

func condition(field windows.GUID, match, typ uint32, value uintptr) fwpmFilterCondition0 {
	return fwpmFilterCondition0{fieldKey: field, matchType: match, value: fwpValue0{typ: typ, value: value}}
}

// v4 — адрес IPv4 в порядке байт процессора, как его ждёт WFP.
func v4(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

// appID возвращает идентификатор программы в формате WFP; память
// освобождается freeWFP.
func appID(path string) (*fwpByteBlob, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var blob *fwpByteBlob
	err = wfpCall(procGetAppIDFromFile, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&blob)))
	runtime.KeepAlive(p)
	return blob, err
}

func freeWFP(p unsafe.Pointer) {
	_, _, _ = procFreeMemory.Call(uintptr(unsafe.Pointer(&p)))
}

// userDescriptor разрешает фильтр соединениям учётной записи текущего
// процесса: служба и запущенный ею sing-box работают от SYSTEM, окно — нет.
func userDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString(fmt.Sprintf("D:(A;;%#x;;;%s)", fwpActrlMatchFilter, user.User.Sid))
}
