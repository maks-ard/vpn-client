package openvpn

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Link — поднятый туннель: через какой адаптер и что прислал сервер.
type Link struct {
	// Interface — имя адаптера OpenVPN в системе.
	Interface string
	// Server — адрес сервера OpenVPN, к которому подключились.
	Server netip.Addr
	// Local — адрес компьютера в сети компании.
	Local netip.Addr
	// DNS — DNS-серверы компании.
	DNS []netip.Addr
	// Domains — DNS-домены компании (DOMAIN, DOMAIN-SEARCH, dns search-domains).
	Domains []string
	// Routes — подсети, которые сервер направил в туннель.
	Routes []netip.Prefix
}

// Equal сравнивает всё, от чего зависит конфиг sing-box.
func (l *Link) Equal(o *Link) bool {
	if l == nil || o == nil {
		return l == o
	}
	return l.Interface == o.Interface && l.Server == o.Server && l.Local == o.Local &&
		slices.Equal(l.DNS, o.DNS) && slices.Equal(l.Domains, o.Domains) && slices.Equal(l.Routes, o.Routes)
}

// EventKind — что произошло с туннелем.
type EventKind int

const (
	// EventUp — туннель поднялся, Event.Link заполнен.
	EventUp EventKind = iota + 1
	// EventDown — туннель упал, OpenVPN переподключается или завершается.
	EventDown
	// EventAuthFailed — сервер отклонил логин и пароль.
	EventAuthFailed
)

type Event struct {
	Kind EventKind
	Link *Link
}

// Watcher следит за журналом OpenVPN (verb 3). Формат сообщений сверен с
// исходниками OpenVPN 2.6 и проверен на 2.6.19.
type Watcher struct {
	// Имя адаптера помним между переподключениями: с persist-tun адаптер
	// не открывается заново, и сообщения о нём не будет.
	iface   string
	pending Link
	up      bool
}

// Feed разбирает строку журнала. ok — строка изменила состояние туннеля.
func (w *Watcher) Feed(line string) (Event, bool) {
	switch {
	case strings.Contains(line, "PUSH: Received control message: '"):
		// Длинный ответ сервер присылает частями (push-continuation),
		// поэтому накапливаем до «Initialization Sequence Completed».
		msg := line[strings.Index(line, "'")+1:]
		msg = strings.TrimSuffix(strings.TrimSpace(msg), "'")
		if opts, ok := strings.CutPrefix(msg, "PUSH_REPLY,"); ok {
			w.pending.parsePush(opts)
		}
	case strings.Contains(line, "Initialization Sequence Completed"):
		link := w.pending
		link.Interface = w.iface
		link.DNS = slices.Clone(link.DNS)
		link.Domains = slices.Clone(link.Domains)
		link.Routes = slices.Clone(link.Routes)
		w.pending = Link{Server: w.pending.Server}
		w.up = true
		return Event{Kind: EventUp, Link: &link}, true
	case strings.Contains(line, "AUTH: Received control message: AUTH_FAILED"):
		w.reset()
		return Event{Kind: EventAuthFailed}, true
	case strings.Contains(line, "SIGUSR1[") || strings.Contains(line, "SIGHUP[") ||
		strings.Contains(line, "SIGTERM[") || strings.Contains(line, "Exiting due to fatal error"):
		wasUp := w.up
		w.reset()
		if wasUp {
			return Event{Kind: EventDown}, true
		}
	default:
		if name, ok := deviceName(line); ok {
			w.iface = name
		} else if addr, ok := remoteAddr(line); ok {
			w.pending.Server = addr
		}
	}
	return Event{}, false
}

func (w *Watcher) reset() {
	w.pending = Link{}
	w.up = false
}

// deviceName находит имя адаптера: «ovpn-dco device [OpenVPN Data Channel
// Offload] opened» в Windows, «TUN/TAP device tun0 opened» и «DCO device tun0
// opened» в Linux.
func deviceName(line string) (string, bool) {
	before, ok := strings.CutSuffix(strings.TrimSpace(line), " opened")
	if !ok {
		return "", false
	}
	if i := strings.LastIndex(before, " device ["); i >= 0 && strings.HasSuffix(before, "]") {
		return before[i+len(" device [") : len(before)-1], true
	}
	for _, marker := range []string{"TUN/TAP device ", "DCO device "} {
		if i := strings.LastIndex(before, marker); i >= 0 {
			name := before[i+len(marker):]
			if name != "" && !strings.Contains(name, " ") {
				return name, true
			}
		}
	}
	return "", false
}

// remoteAddr находит адрес сервера в «UDPv4 link remote: [AF_INET]1.2.3.4:1194»
// и «TCP connection established with [AF_INET]1.2.3.4:443».
func remoteAddr(line string) (netip.Addr, bool) {
	var rest string
	for _, marker := range []string{"link remote: ", "TCP connection established with "} {
		if i := strings.Index(line, marker); i >= 0 {
			rest = line[i+len(marker):]
			break
		}
	}
	if rest == "" {
		return netip.Addr{}, false
	}
	rest = strings.TrimPrefix(strings.TrimPrefix(rest, "[AF_INET6]"), "[AF_INET]")
	rest = strings.Fields(rest + " ")[0]
	if ap, err := netip.ParseAddrPort(rest); err == nil {
		return ap.Addr().Unmap(), true
	}
	if i := strings.LastIndex(rest, ":"); i > 0 {
		rest = rest[:i]
	}
	addr, err := netip.ParseAddr(strings.Trim(rest, "[]"))
	return addr.Unmap(), err == nil
}

// parsePush добавляет к l настройки из PUSH_REPLY. Нужно только то, что
// влияет на маршрутизацию в sing-box; остальное применяет сам OpenVPN.
func (l *Link) parsePush(opts string) {
	for _, opt := range strings.Split(opts, ",") {
		f := strings.Fields(opt)
		if len(f) < 2 {
			continue
		}
		switch strings.ToLower(f[0]) {
		case "route":
			addr, err := netip.ParseAddr(f[1])
			if err != nil || !addr.Is4() {
				continue
			}
			// Маршрут через net_gateway — исключение из туннеля, а не в туннель.
			if len(f) > 3 && strings.EqualFold(f[3], "net_gateway") {
				continue
			}
			bits := 32
			if len(f) > 2 {
				if bits = maskBits(f[2]); bits < 0 {
					continue
				}
			}
			l.addRoute(netip.PrefixFrom(addr, bits).Masked())
		case "route-ipv6":
			if p, err := netip.ParsePrefix(f[1]); err == nil {
				l.addRoute(p.Masked())
			}
		case "ifconfig":
			if addr, err := netip.ParseAddr(f[1]); err == nil {
				l.Local = addr
			}
		case "dhcp-option":
			if len(f) < 3 {
				continue
			}
			switch strings.ToUpper(f[1]) {
			case "DNS", "DNS6":
				l.addDNS(f[2])
			case "DOMAIN", "DOMAIN-SEARCH", "ADAPTER_DOMAIN_SUFFIX":
				l.addDomains(f[2:])
			}
		case "dns":
			// dns server 1 address 10.0.0.1 [10.0.0.2:5353 …]
			// dns server 1 resolve-domains corp.example …
			// dns search-domains corp.example …
			switch {
			case strings.EqualFold(f[1], "search-domains"):
				l.addDomains(f[2:])
			case strings.EqualFold(f[1], "server") && len(f) > 4 && strings.EqualFold(f[3], "address"):
				for _, a := range f[4:] {
					l.addDNS(a)
				}
			case strings.EqualFold(f[1], "server") && len(f) > 4 && strings.EqualFold(f[3], "resolve-domains"):
				l.addDomains(f[4:])
			}
		}
	}
}

func (l *Link) addRoute(p netip.Prefix) {
	if !slices.Contains(l.Routes, p) {
		l.Routes = append(l.Routes, p)
	}
}

// addDNS понимает «10.0.0.1», «10.0.0.1:53» и «[fd00::1]:53». DNS на
// нестандартном порту пропускаем: sing-box получает только адрес.
func (l *Link) addDNS(s string) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		ap, err := netip.ParseAddrPort(s)
		if err != nil || ap.Port() != 53 {
			return
		}
		addr = ap.Addr()
	}
	if !slices.Contains(l.DNS, addr) {
		l.DNS = append(l.DNS, addr)
	}
}

func (l *Link) addDomains(domains []string) {
	for _, d := range domains {
		d = strings.ToLower(strings.Trim(d, ". "))
		if d != "" && strings.Contains(d, ".") && !slices.Contains(l.Domains, d) {
			l.Domains = append(l.Domains, d)
		}
	}
}

// maskBits переводит маску 255.255.0.0 в длину префикса; -1 — маска не
// непрерывная.
func maskBits(s string) int {
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 32 {
		return n
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is4() {
		return -1
	}
	b := addr.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	bits := 0
	for v&0x80000000 != 0 {
		bits++
		v <<= 1
	}
	if v != 0 {
		return -1
	}
	return bits
}
