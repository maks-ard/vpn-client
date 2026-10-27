// Package singbox собирает конфиг sing-box (формат 1.14) из профиля.
package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/maks-ard/vpn-client/internal/ovpn"
	"github.com/maks-ard/vpn-client/internal/profile"
	"github.com/maks-ard/vpn-client/internal/subscription"
	"github.com/maks-ard/vpn-client/internal/vless"
)

// Теги внутри конфига.
const (
	TagTUN       = "tun-in"
	TagDirect    = "direct"
	TagProxy     = "proxy"
	TagAuto      = "auto"
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

// Input — всё, из чего собирается конфиг. Servers и OpenVPN могут быть пустыми.
type Input struct {
	Profile *profile.Profile
	// Servers — VLESS-серверы: одна ссылка из профиля или список из подписки.
	Servers []subscription.Server
	// Subscription — подписка, если серверы взяты из неё.
	Subscription *subscription.Subscription
	OpenVPN      *ovpn.Config
	// API — включить Clash API (статистика, выбор сервера) на этом адресе.
	// Если nil, используется singbox.clash_api из профиля.
	API *API
	// LocalSets — уже скачанные и проверенные файлы rule-set'ов категорий
	// (тег → путь). Если задано, категории используют только их, а набор без
	// файла пропускается с предупреждением: недоступная ссылка не должна
	// мешать запуску sing-box. Если nil, наборы подключаются по ссылке.
	LocalSets map[string]string
	// Inbound заменяет TUN другим inbound (например, mixed): нужно для
	// тестов, где нет прав на создание TUN.
	Inbound M
	// CorpLink — корпоративная сеть через системный OpenVPN; nil — через
	// endpoint OpenVPN внутри sing-box.
	CorpLink *CorpLink
}

type API struct {
	Addr   string
	Secret string
}

// Load читает профиль и связанные с ним файлы, а подписку скачивает
// (или берёт из кэша в dataDir).
func Load(ctx context.Context, path, dataDir string) (*Input, error) {
	p, err := profile.Load(path)
	if err != nil {
		return nil, err
	}
	return FromProfile(ctx, p, dataDir)
}

// FromProfile — то же, что Load, для уже прочитанного профиля.
func FromProfile(ctx context.Context, p *profile.Profile, dataDir string) (*Input, error) {
	in := &Input{Profile: p}
	switch {
	case p.VLESS != "":
		link, err := vless.Parse(p.VLESS)
		if err != nil {
			return nil, fmt.Errorf("vless: %w", err)
		}
		in.Servers = []subscription.Server{{Name: link.Name, Links: []*vless.Link{link}}}
	case p.Subscription != nil:
		sub, err := subscription.Get(ctx, p.Subscription.URL, p.Subscription.UserAgent, dataDir)
		if err != nil {
			return nil, err
		}
		in.Subscription = sub
		in.Servers = sub.Servers
	}
	if p.OpenVPN != nil {
		var err error
		if in.OpenVPN, err = loadOVPN(p); err != nil {
			return nil, err
		}
	}
	return in, nil
}

// FromProfileOffline — то же, что FromProfile, но подписку берёт из кэша и в
// сеть не ходит. Если кэша нет, серверов в результате не будет. Нужен для
// проверки адреса, которой незачем качать подписку.
func FromProfileOffline(p *profile.Profile, dataDir string) (*Input, error) {
	in := &Input{Profile: p}
	switch {
	case p.VLESS != "":
		link, err := vless.Parse(p.VLESS)
		if err != nil {
			return nil, fmt.Errorf("vless: %w", err)
		}
		in.Servers = []subscription.Server{{Name: link.Name, Links: []*vless.Link{link}}}
	case p.Subscription != nil:
		if sub, err := subscription.Cached(dataDir); err == nil {
			in.Subscription = sub
			in.Servers = sub.Servers
		}
	}
	if p.OpenVPN != nil {
		var err error
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
	var w []string
	if sub := in.Subscription; sub != nil {
		if sub.FromCache {
			w = append(w, fmt.Sprintf("подписка: не удалось обновить (%v), используется список от %s",
				sub.FetchError, sub.FetchedAt.Format("02.01.2006 15:04")))
		}
		// Пропущенные серверы (например, с XHTTP) в списке не видны, и при
		// рабочих соседях замечание о них висело бы постоянно. Говорим о них,
		// только если пропущен именно выбранный сервер: тогда подключение
		// молча ушло бы на «Авто». Если не подошёл ни один, ошибку с причинами
		// вернёт сама подписка. Полный список пишется в журнал (Skipped).
		if name := selectedServer(in.Profile); name != "" && !hasServer(in.Servers, name) {
			for _, s := range sub.SkippedFor(name) {
				w = append(w, "подписка: выбранный сервер недоступен, используется «Авто»: "+s)
			}
		}
	}
	for _, s := range resolveCategories(in).warnings {
		w = append(w, "категории: "+s)
	}
	if in.OpenVPN == nil {
		return w
	}
	// Замечания разбора .ovpn касаются endpoint sing-box: системный OpenVPN
	// понимает конфиг сам.
	if in.CorpLink == nil {
		for _, s := range in.OpenVPN.Warnings {
			w = append(w, "openvpn: "+s)
		}
	}
	if in.OpenVPN.RedirectGateway {
		w = append(w, "openvpn: redirect-gateway в .ovpn проигнорирован, через OpenVPN идут только корпоративные адреса")
	}
	return w
}

// Skipped — серверы подписки, которые пропущены без предупреждения в окне.
// Их стоит записать в журнал.
func (in *Input) Skipped() []string {
	if in.Subscription == nil {
		return nil
	}
	return in.Subscription.Skipped
}

func selectedServer(p *profile.Profile) string {
	if p.Subscription == nil {
		return ""
	}
	return p.Subscription.Server
}

func hasServer(servers []subscription.Server, name string) bool {
	for _, s := range servers {
		if s.Name == name {
			return true
		}
	}
	return false
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
	hasProxy := len(in.Servers) > 0
	hasCorp := in.OpenVPN != nil
	if !hasProxy && len(p.Routing.ProxyDomains) > 0 {
		return nil, fmt.Errorf("routing.proxy_domains задан, но нет ни ссылки vless, ни подписки")
	}

	outbounds := []any{M{"type": "direct", "tag": TagDirect}}
	if hasProxy {
		obs, err := proxyOutbounds(in)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, obs...)
	}
	var endpoints []any
	if hasCorp && in.CorpLink != nil {
		// Соединения через адаптер системного OpenVPN; пока его нет, правила
		// с OpenVPN заменены отказом, и outbound не нужен.
		if !in.corpOffline() {
			corp := M{"type": "direct", "tag": TagCorp, "bind_interface": in.CorpLink.Interface}
			// Имена, которые outbound разрешает сам, — тоже через DNS компании.
			if server := in.corpDNSServer(); server == TagDNSCorp {
				corp["domain_resolver"] = server
			}
			outbounds = append(outbounds, corp)
		}
	} else if hasCorp {
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
		"inbounds":     []any{inbound(in)},
		"outbounds":    outbounds,
		"route":        routeSection(in, hasProxy, hasCorp, final),
		"experimental": experimental(in),
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	if needRuleSets(in) {
		// Правила качаем напрямую: если VLESS недоступен, корпоративный доступ
		// и прямой трафик всё равно должны подняться. После первой загрузки
		// правила берутся из cache.db.
		cfg["http_clients"] = []any{M{"tag": "rule-sets"}}
	}
	return cfg, nil
}

func inbound(in *Input) M {
	if in.Inbound != nil {
		return in.Inbound
	}
	tun := tunInbound(in.Profile)
	if in.CorpLink != nil && len(in.CorpLink.Servers) > 0 {
		var exclude []string
		for _, a := range in.CorpLink.Servers {
			exclude = append(exclude, netip.PrefixFrom(a, a.BitLen()).String())
		}
		tun["route_exclude_address"] = exclude
	}
	return tun
}

// Адреса TUN. По ним kill switch отличает соединения, идущие через VPN.
var (
	TunAddress4 = netip.MustParsePrefix("172.19.0.1/30")
	TunAddress6 = netip.MustParsePrefix("fdfe:dcba:9876::1/126")
)

// CorpInterfaceName — имя адаптера OpenVPN в Windows при
// openvpn.system_interface; по нему служба находит адаптер для маршрутов.
const CorpInterfaceName = "vpn-client-corp"

func tunInbound(p *profile.Profile) M {
	address := []string{TunAddress4.String()}
	if p.TUN.IPv6 {
		address = append(address, TunAddress6.String())
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

// labeledRule — правило маршрутов и его происхождение. Подпись нужна проверке
// адреса («сработало правило …»); в конфиг она не попадает.
type labeledRule struct {
	rule  M
	label string
}

// routeRuleList — правила, которые проверяются по порядку после sniff и
// перехвата DNS. И конфиг, и проверка адреса берут их отсюда, поэтому
// расходиться не могут.
func routeRuleList(in *Input, cats resolved, hasProxy, hasCorp bool) []labeledRule {
	p := in.Profile
	var rules []labeledRule
	add := func(label string, rule M) { rules = append(rules, labeledRule{rule: rule, label: label}) }

	if hasCorp {
		if len(p.Corporate.Domains) > 0 {
			add("корпоративные домены", M{"domain_suffix": p.Corporate.Domains, "outbound": TagCorp})
		}
		// Подсети и домены, которые прислал сервер OpenVPN.
		if l := in.CorpLink; l != nil {
			if len(l.Domains) > 0 {
				add("домены от сервера OpenVPN", M{"domain_suffix": l.Domains, "outbound": TagCorp})
			}
			if routes := in.corpRoutes(); len(routes) > 0 {
				add("маршруты от сервера OpenVPN", M{"ip_cidr": routes, "outbound": TagCorp})
			}
		} else {
			add("маршруты от сервера OpenVPN", M{"preferred_by": []string{TagCorp}, "outbound": TagCorp})
		}
		if len(p.Corporate.Subnets) > 0 {
			add("корпоративные подсети", M{"ip_cidr": p.Corporate.Subnets, "outbound": TagCorp})
		}
	}
	// Категории, направленные в OpenVPN, тоже выше частных сетей.
	rules = append(rules, cats.routeRules(true)...)
	add("локальная сеть", M{"ip_is_private": true, "outbound": TagDirect})
	if len(p.Routing.DirectProcesses) > 0 {
		add("программа из direct_processes", M{"process_name": p.Routing.DirectProcesses, "outbound": TagDirect})
	}
	if hasProxy && len(p.Routing.ProxyDomains) > 0 {
		add("список proxy_domains", M{"domain_suffix": p.Routing.ProxyDomains, "outbound": TagProxy})
	}
	if len(p.Routing.DirectDomains) > 0 {
		add("список direct_domains", M{"domain_suffix": p.Routing.DirectDomains, "outbound": TagDirect})
	}
	rules = append(rules, cats.routeRules(false)...)
	if useRuleSets(in) {
		add("российские сайты", M{"domain_suffix": russianTLDs, "outbound": TagDirect})
		add("российские сайты", M{"rule_set": []string{ruleSetGeositeRU, ruleSetGeoIPRU}, "outbound": TagDirect})
	}
	return rules
}

func routeSection(in *Input, hasProxy, hasCorp bool, final string) M {
	cats := resolveCategories(in)
	rules := []any{
		M{"action": "sniff"},
		M{"protocol": "dns", "action": "hijack-dns"},
	}
	for _, r := range routeRuleList(in, cats, hasProxy, hasCorp) {
		rules = append(rules, r.rule)
	}
	if in.corpOffline() {
		rules = rejectCorp(rules)
	}
	route := M{
		"final":                   final,
		"auto_detect_interface":   true,
		"default_domain_resolver": TagDNSDirect,
	}
	if sets := ruleSetDefs(in, cats); len(sets) > 0 {
		route["rule_set"] = sets
		if needRuleSets(in) {
			route["default_http_client"] = "rule-sets"
		}
	}
	route["rules"] = rules
	return route
}

// useRuleSets: правила для России нужны, только когда есть куда отправлять
// остальной трафик.
func useRuleSets(in *Input) bool {
	return len(in.Servers) > 0 && in.Profile.RussiaDirect()
}

// needRuleSets: нужны ли вообще скачиваемые rule-set'ы (для России или категорий).
func needRuleSets(in *Input) bool {
	if useRuleSets(in) {
		return true
	}
	for _, s := range resolveCategories(in).sets {
		if s.path == "" {
			return true
		}
	}
	return false
}

func ruleSetDefsRaw(in *Input, cats resolved) []ruleSetDef {
	var defs []ruleSetDef
	if useRuleSets(in) {
		for _, tag := range []string{ruleSetGeositeRU, ruleSetGeoIPRU} {
			defs = append(defs, ruleSetDef{tag: tag, url: ruleSetURLs[tag]})
		}
	}
	return append(defs, cats.sets...)
}

// ruleSetDefs — все rule-set'ы конфига: для России, затем для категорий.
func ruleSetDefs(in *Input, cats resolved) []any {
	var out []any
	for _, d := range ruleSetDefsRaw(in, cats) {
		if d.path != "" {
			out = append(out, M{"type": "local", "tag": d.tag, "format": "binary", "path": d.path})
			continue
		}
		out = append(out, M{
			"type":            "remote",
			"tag":             d.tag,
			"format":          "binary",
			"url":             d.url,
			"update_interval": "72h",
		})
	}
	return out
}

func dnsSection(in *Input, hasProxy, hasCorp bool) (M, error) {
	p := in.Profile
	cats := resolveCategories(in)
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
		var corpRules []any
		if l := in.CorpLink; l != nil {
			if in.corpDNSServer() == TagDNSCorp {
				servers = append(servers, M{
					"type":           "udp",
					"tag":            TagDNSCorp,
					"server":         l.dnsServer().String(),
					"bind_interface": l.Interface,
				})
			}
			if len(p.Corporate.Domains) > 0 {
				corpRules = append(corpRules, M{"domain_suffix": p.Corporate.Domains, "server": TagDNSCorp})
			}
			if len(l.Domains) > 0 {
				corpRules = append(corpRules, M{"domain_suffix": l.Domains, "server": TagDNSCorp})
			}
		} else {
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
				corpRules = append(corpRules, M{"domain_suffix": p.Corporate.Domains, "server": TagDNSCorp})
			}
			corpRules = append(corpRules, M{"preferred_by": []string{TagDNSCorp}, "server": TagDNSCorp})
		}
		corpRules = append(corpRules, cats.dnsRules(true)...)
		rules = append(rules, retargetCorpDNS(corpRules, in.corpDNSServer())...)
	}
	if hasProxy && len(p.Routing.ProxyDomains) > 0 {
		rules = append(rules, M{"domain_suffix": p.Routing.ProxyDomains, "server": TagDNSRemote})
	}
	if len(p.Routing.DirectDomains) > 0 {
		rules = append(rules, M{"domain_suffix": p.Routing.DirectDomains, "server": TagDNSDirect})
	}
	rules = append(rules, cats.dnsRules(false)...)
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

func experimental(in *Input) M {
	exp := M{"cache_file": M{"enabled": true, "path": "cache.db"}}
	switch {
	case in.API != nil:
		exp["clash_api"] = M{"external_controller": in.API.Addr, "secret": in.API.Secret}
	case in.Profile.SingBox.ClashAPI != "":
		exp["clash_api"] = M{"external_controller": in.Profile.SingBox.ClashAPI}
	}
	return exp
}
