// Package singbox собирает конфиг sing-box (формат 1.14) из профиля.
package singbox

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/maks-ard/vpn-client/internal/ovpn"
	"github.com/maks-ard/vpn-client/internal/profile"
	"github.com/maks-ard/vpn-client/internal/vless"
)

// Теги внутри конфига.
const (
	TagTUN       = "tun-in"
	TagDirect    = "direct"
	TagProxy     = "proxy"
	TagCorp      = "corp"
	TagDNSDirect = "dns-direct"
	TagDNSRemote = "dns-remote"
	TagDNSCorp   = "dns-corp"
)

// MinVersion — минимальная версия sing-box, понимающая генерируемый конфиг
// (endpoint openvpn-client появился в 1.14).
const MinVersion = "1.14.0"

// Российские домены верхнего уровня: .ru, .su, .рф.
var russianTLDs = []string{"ru", "su", "xn--p1ai"}

const (
	ruleSetGeositeRU = "geosite-category-ru"
	ruleSetGeoIPRU   = "geoip-ru"
)

var ruleSetURLs = map[string]string{
	ruleSetGeositeRU: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs",
	ruleSetGeoIPRU:   "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs",
}

type M = map[string]any

// Input — всё, из чего собирается конфиг. VLESS и OpenVPN могут быть nil.
type Input struct {
	Profile *profile.Profile
	VLESS   *vless.Link
	OpenVPN *ovpn.Config
}

// Load читает профиль и связанные с ним файлы.
func Load(path string) (*Input, error) {
	p, err := profile.Load(path)
	if err != nil {
		return nil, err
	}
	in := &Input{Profile: p}
	if p.VLESS != "" {
		if in.VLESS, err = vless.Parse(p.VLESS); err != nil {
			return nil, fmt.Errorf("vless: %w", err)
		}
	}
	if p.OpenVPN != nil {
		if in.OpenVPN, err = loadOVPN(p); err != nil {
			return nil, err
		}
	}
	return in, nil
}

func loadOVPN(p *profile.Profile) (*ovpn.Config, error) {
	c, err := ovpn.ParseFile(p.Resolve(p.OpenVPN.Config))
	if err != nil {
		return nil, fmt.Errorf("openvpn: %w", err)
	}
	return c, nil
}

// Warnings — некритичные замечания, которые стоит показать пользователю.
func (in *Input) Warnings() []string {
	if in.OpenVPN == nil {
		return nil
	}
	var w []string
	for _, s := range in.OpenVPN.Warnings {
		w = append(w, "openvpn: "+s)
	}
	if in.OpenVPN.RedirectGateway {
		w = append(w, "openvpn: redirect-gateway в .ovpn проигнорирован, через OpenVPN идут только корпоративные адреса")
	}
	return w
}

// Build возвращает конфиг sing-box в виде JSON.
func Build(in *Input) ([]byte, error) {
	cfg, err := build(in)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func build(in *Input) (M, error) {
	p := in.Profile
	hasProxy := in.VLESS != nil
	hasCorp := in.OpenVPN != nil
	if !hasProxy && len(p.Routing.ProxyDomains) > 0 {
		return nil, fmt.Errorf("routing.proxy_domains задан, но нет ссылки vless")
	}

	outbounds := []any{M{"type": "direct", "tag": TagDirect}}
	if hasProxy {
		ob, err := vlessOutbound(in.VLESS)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, ob)
	}
	var endpoints []any
	if hasCorp {
		ep, err := openVPNEndpoint(in.OpenVPN, p)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, ep)
	}

	final := TagDirect
	if hasProxy {
		final = TagProxy
	}

	dns, err := dnsSection(in, hasProxy, hasCorp)
	if err != nil {
		return nil, err
	}

	cfg := M{
		"log":          M{"level": p.SingBox.LogLevel, "timestamp": true},
		"dns":          dns,
		"inbounds":     []any{tunInbound(p)},
		"outbounds":    outbounds,
		"route":        routeSection(in, hasProxy, hasCorp, final),
		"experimental": experimental(p),
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	if useRuleSets(in) {
		// Правила качаем напрямую: если VLESS недоступен, корпоративный доступ
		// и прямой трафик всё равно должны подняться. После первой загрузки
		// правила берутся из cache.db.
		cfg["http_clients"] = []any{M{"tag": "rule-sets"}}
	}
	return cfg, nil
}

func tunInbound(p *profile.Profile) M {
	address := []string{"172.19.0.1/30"}
	if p.TUN.IPv6 {
		address = append(address, "fdfe:dcba:9876::1/126")
	}
	return M{
		"type":           "tun",
		"tag":            TagTUN,
		"interface_name": "vpn-client",
		"address":        address,
		"mtu":            p.TUN.MTU,
		"auto_route":     true,
		// На Windows strict_route закрывает DNS-утечки через другие адаптеры
		// и делает IPv6 недоступным, если у TUN нет IPv6-адреса.
		"strict_route": true,
		"stack":        p.TUN.Stack,
	}
}

func routeSection(in *Input, hasProxy, hasCorp bool, final string) M {
	p := in.Profile
	rules := []any{
		M{"action": "sniff"},
		M{"protocol": "dns", "action": "hijack-dns"},
	}
	if hasCorp {
		if len(p.Corporate.Domains) > 0 {
			rules = append(rules, M{"domain_suffix": p.Corporate.Domains, "outbound": TagCorp})
		}
		// Подсети и домены, которые прислал сервер OpenVPN.
		rules = append(rules, M{"preferred_by": []string{TagCorp}, "outbound": TagCorp})
		if len(p.Corporate.Subnets) > 0 {
			rules = append(rules, M{"ip_cidr": p.Corporate.Subnets, "outbound": TagCorp})
		}
	}
	rules = append(rules, M{"ip_is_private": true, "outbound": TagDirect})
	if len(p.Routing.DirectProcesses) > 0 {
		rules = append(rules, M{"process_name": p.Routing.DirectProcesses, "outbound": TagDirect})
	}
	if hasProxy && len(p.Routing.ProxyDomains) > 0 {
		rules = append(rules, M{"domain_suffix": p.Routing.ProxyDomains, "outbound": TagProxy})
	}
	if len(p.Routing.DirectDomains) > 0 {
		rules = append(rules, M{"domain_suffix": p.Routing.DirectDomains, "outbound": TagDirect})
	}
	route := M{
		"final":                   final,
		"auto_detect_interface":   true,
		"default_domain_resolver": TagDNSDirect,
	}
	if useRuleSets(in) {
		rules = append(rules,
			M{"domain_suffix": russianTLDs, "outbound": TagDirect},
			M{"rule_set": []string{ruleSetGeositeRU, ruleSetGeoIPRU}, "outbound": TagDirect},
		)
		route["rule_set"] = ruleSets()
		route["default_http_client"] = "rule-sets"
	}
	route["rules"] = rules
	return route
}

// useRuleSets: правила для России нужны, только когда есть куда отправлять
// остальной трафик.
func useRuleSets(in *Input) bool {
	return in.VLESS != nil && in.Profile.RussiaDirect()
}

func ruleSets() []any {
	var out []any
	for _, tag := range []string{ruleSetGeositeRU, ruleSetGeoIPRU} {
		out = append(out, M{
			"type":            "remote",
			"tag":             tag,
			"format":          "binary",
			"url":             ruleSetURLs[tag],
			"update_interval": "72h",
		})
	}
	return out
}

func dnsSection(in *Input, hasProxy, hasCorp bool) (M, error) {
	p := in.Profile
	servers := []any{M{"type": "udp", "tag": TagDNSDirect, "server": p.DNS.Direct}}
	var rules []any
	final := TagDNSDirect

	if hasProxy {
		remote, err := httpsDNSServer(p.DNS.Remote)
		if err != nil {
			return nil, err
		}
		servers = append(servers, remote)
		final = TagDNSRemote
	}
	if hasCorp {
		servers = append(servers, M{
			"type":     "openvpn",
			"tag":      TagDNSCorp,
			"endpoint": TagCorp,
			// Корпоративные домены резолвим DNS-серверами из OpenVPN,
			// даже если сервер не прислал для них DOMAIN-ROUTE.
			"accept_default_resolvers": true,
			"accept_search_domain":     true,
		})
		if len(p.Corporate.Domains) > 0 {
			rules = append(rules, M{"domain_suffix": p.Corporate.Domains, "server": TagDNSCorp})
		}
		rules = append(rules, M{"preferred_by": []string{TagDNSCorp}, "server": TagDNSCorp})
	}
	if hasProxy && len(p.Routing.ProxyDomains) > 0 {
		rules = append(rules, M{"domain_suffix": p.Routing.ProxyDomains, "server": TagDNSRemote})
	}
	if len(p.Routing.DirectDomains) > 0 {
		rules = append(rules, M{"domain_suffix": p.Routing.DirectDomains, "server": TagDNSDirect})
	}
	if useRuleSets(in) {
		rules = append(rules,
			M{"domain_suffix": russianTLDs, "server": TagDNSDirect},
			M{"rule_set": []string{ruleSetGeositeRU}, "server": TagDNSDirect},
		)
	}

	strategy := "ipv4_only"
	if p.TUN.IPv6 {
		strategy = "prefer_ipv4"
	}
	dns := M{
		"servers":  servers,
		"final":    final,
		"strategy": strategy,
	}
	if len(rules) > 0 {
		dns["rules"] = rules
	}
	return dns, nil
}

// httpsDNSServer понимает "1.1.1.1", "dns.google" и "https://host/path".
func httpsDNSServer(s string) (M, error) {
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("dns.remote: ожидается адрес DoH-сервера, получено %q", s)
	}
	server := M{
		"type":   "https",
		"tag":    TagDNSRemote,
		"server": u.Hostname(),
		"detour": TagProxy,
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("dns.remote: неверный порт %q", port)
		}
		server["server_port"] = n
	}
	if u.Path != "" && u.Path != "/dns-query" {
		server["path"] = u.Path
	}
	if _, err := netip.ParseAddr(u.Hostname()); err != nil {
		server["domain_resolver"] = TagDNSDirect
	}
	return server, nil
}

func experimental(p *profile.Profile) M {
	exp := M{"cache_file": M{"enabled": true, "path": "cache.db"}}
	if p.SingBox.ClashAPI != "" {
		exp["clash_api"] = M{"external_controller": p.SingBox.ClashAPI}
	}
	return exp
}
