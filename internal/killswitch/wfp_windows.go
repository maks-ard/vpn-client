package killswitch

// Типы и функции Windows Filtering Platform из fwpmtypes.h и fwpmu.h.
// Раскладка структур сверена с wireguard-windows (tunnel/firewall, MIT) и
// проверяется тестом на размеры.

import (
	"syscall"

	"golang.org/x/sys/windows"
)

type fwpByteBlob struct {
	size uint32
	data *byte
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32
}

type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

// fwpValue0 — FWP_VALUE0 и FWP_CONDITION_VALUE0: тип и объединение размером
// в указатель (мелкие числа лежат в нём самом, остальное — по указателю).
type fwpValue0 struct {
	typ   uint32
	value uintptr
}

type fwpmFilterCondition0 struct {
	fieldKey  windows.GUID
	matchType uint32
	value     fwpValue0
}

type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID
}

type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	// В C следующее поле — объединение с UINT64, оно выровнено на 8 байт.
	_                  [4]byte
	providerContextKey windows.GUID
	reserved           *windows.GUID
	filterID           uint64
	effectiveWeight    fwpValue0
}

type fwpV4AddrAndMask struct {
	addr uint32
	mask uint32
}

type fwpV6AddrAndMask struct {
	addr         [16]byte
	prefixLength uint8
}

const (
	fwpUint8              = 1
	fwpUint16             = 2
	fwpUint32             = 3
	fwpByteArray16        = 11
	fwpByteBlobType       = 12
	fwpSecurityDescriptor = 14
	fwpV4AddrMask         = 0x100
	fwpV6AddrMask         = 0x101

	fwpMatchEqual       = 0
	fwpMatchFlagsAllSet = 6

	fwpActionBlock  = 0x1001
	fwpActionPermit = 0x1002

	fwpmSessionFlagDynamic = 1
	fwpConditionIsLoopback = 1
	// fwpActrlMatchFilter — право, которое дескриптор в условии ALE_USER_ID
	// выдаёт учётной записи, чьи соединения подходят под фильтр.
	fwpActrlMatchFilter = 1

	rpcCAuthnWinNT = 10

	ipprotoICMPv6 = 58
	ipprotoUDP    = 17
)

var (
	layerConnectV4 = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	layerConnectV6 = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}

	condRemoteAddress = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8, Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	condLocalAddress  = windows.GUID{Data1: 0xd9ee00de, Data2: 0xc1ef, Data3: 0x4617, Data4: [8]byte{0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57}}
	condProtocol      = windows.GUID{Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a, Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	condLocalPort     = windows.GUID{Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f, Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}}
	condRemotePort    = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	condAppID         = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	condUserID        = windows.GUID{Data1: 0xaf043a0a, Data2: 0xb34d, Data3: 0x4f86, Data4: [8]byte{0x97, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66}}
	condFlags         = windows.GUID{Data1: 0x632ce23b, Data2: 0x5167, Data3: 0x435c, Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}
	// Для ICMP поля портов означают тип и код сообщения.
	condICMPType = condLocalPort
)

var (
	fwpuclnt              = windows.NewLazySystemDLL("fwpuclnt.dll")
	procEngineOpen        = fwpuclnt.NewProc("FwpmEngineOpen0")
	procEngineClose       = fwpuclnt.NewProc("FwpmEngineClose0")
	procSubLayerAdd       = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFilterAdd         = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFilterDeleteByID  = fwpuclnt.NewProc("FwpmFilterDeleteById0")
	procTransactionBegin  = fwpuclnt.NewProc("FwpmTransactionBegin0")
	procTransactionCommit = fwpuclnt.NewProc("FwpmTransactionCommit0")
	procTransactionAbort  = fwpuclnt.NewProc("FwpmTransactionAbort0")
	procGetAppIDFromFile  = fwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFreeMemory        = fwpuclnt.NewProc("FwpmFreeMemory0")
)

// wfpCall вызывает функцию WFP: они возвращают код ошибки, а не BOOL.
func wfpCall(p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return err
	}
	r, _, _ := p.Call(args...)
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}
