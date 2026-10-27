package singbox

import "net/netip"

// CorpLink — корпоративная сеть через OpenVPN, установленный в системе
// (openvpn.exe), а не через endpoint openvpn-client внутри sing-box. Адаптер и
// DNS известны только после подключения, поэтому конфиг собирается, когда
// OpenVPN уже поднял туннель, и пересобирается, если они изменились.
type CorpLink struct {
	// Interface — адаптер OpenVPN. Пусто — OpenVPN ещё не подключился:
	// корпоративные соединения и запросы DNS отклоняются, а не уходят мимо
	// туннеля через VLESS или напрямую.
	Interface string
	// DNS — DNS-серверы компании; запросы к ним идут через адаптер.
	DNS []netip.Addr
	// Domains и Routes — DNS-домены и подсети, которые прислал сервер.
	Domains []string
	Routes  []netip.Prefix
	// Servers — адреса серверов OpenVPN. Они исключаются из TUN: иначе
	// OpenVPN ходил бы к своему серверу через sing-box и терял связь при
	// каждом его перезапуске.
	Servers []netip.Addr
}

// dnsServer — первый DNS-сервер компании, IPv4 предпочтительнее: у
// DNS-сервера sing-box один адрес, а IPv6 по умолчанию выключен.
func (l *CorpLink) dnsServer() netip.Addr {
	for _, a := range l.DNS {
		if a.Is4() {
			return a
		}
	}
	return l.DNS[0]
}

func (in *Input) corpOffline() bool {
	return in.CorpLink != nil && in.CorpLink.Interface == ""
}

// corpRoutes — подсети, которые идут в адаптер OpenVPN: присланные сервером
// и заданные в самом .ovpn.
func (in *Input) corpRoutes() []string {
	var out []string
	seen := map[netip.Prefix]bool{}
	add := func(p netip.Prefix) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p.String())
		}
	}
	for _, p := range in.CorpLink.Routes {
		add(p)
	}
	for _, p := range in.OpenVPN.Routes {
		add(p)
	}
	return out
}

// corpDNSServer — DNS-сервер для корпоративных имён: свой сервер через
// адаптер, или dns-direct, если сервер не прислал DNS. Пусто — OpenVPN ещё
// не подключился.
func (in *Input) corpDNSServer() string {
	switch {
	case in.CorpLink == nil:
		return TagDNSCorp
	case in.CorpLink.Interface == "":
		return ""
	case len(in.CorpLink.DNS) == 0:
		return TagDNSDirect
	default:
		return TagDNSCorp
	}
}

// rejectCorp заменяет отправку в OpenVPN отказом, пока OpenVPN не подключился.
func rejectCorp(rules []any) []any {
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		rule, ok := r.(M)
		if ok && rule["outbound"] == TagCorp {
			rule = cloneRule(rule)
			delete(rule, "outbound")
			rule["action"] = "reject"
		}
		out = append(out, rule)
	}
	return out
}

// retargetCorpDNS направляет корпоративные запросы DNS на server, а пока
// OpenVPN не подключился (server пустой), отвечает на них SERVFAIL: имена
// компании не должны уходить чужим DNS-серверам.
func retargetCorpDNS(rules []any, server string) []any {
	if server == TagDNSCorp {
		return rules
	}
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		rule, ok := r.(M)
		if ok && rule["server"] == TagDNSCorp {
			rule = cloneRule(rule)
			if server != "" {
				rule["server"] = server
			} else {
				delete(rule, "server")
				rule["action"] = "predefined"
				rule["rcode"] = "SERVFAIL"
			}
		}
		out = append(out, rule)
	}
	return out
}

func cloneRule(rule M) M {
	out := make(M, len(rule))
	for k, v := range rule {
		out[k] = v
	}
	return out
}
