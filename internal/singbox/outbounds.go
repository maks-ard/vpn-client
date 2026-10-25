package singbox

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/maks-ard/vpn-client/internal/ovpn"
	"github.com/maks-ard/vpn-client/internal/profile"
	"github.com/maks-ard/vpn-client/internal/subscription"
	"github.com/maks-ard/vpn-client/internal/vless"
)

// URLTestURL — адрес для проверки серверов. Берём ресурс, который в России
// заблокирован или замедлен: сервер с выходом в России или под блокировками
// тест не пройдёт и не будет выбран как «самый быстрый».
const URLTestURL = "https://www.youtube.com/generate_204"

// proxyOutbounds: один сервер — это сразу outbound proxy; несколько —
// selector proxy с вариантом auto (urltest выбирает самый быстрый) и
// каждым сервером отдельно, чтобы его можно было выбрать вручную.
// Сервер с несколькими вариантами подключения — urltest по ним: вложенные
// группы sing-box проверяет и показывает в Clash API как обычные серверы.
func proxyOutbounds(in *Input) ([]any, error) {
	reserved := map[string]bool{TagDirect: true, TagProxy: true, TagAuto: true, TagCorp: true}
	unique := func(tag string) string {
		for reserved[tag] {
			tag += " "
		}
		reserved[tag] = true
		return tag
	}
	if len(in.Servers) == 1 {
		return serverOutbounds(in.Servers[0], TagProxy, unique)
	}
	// Имена серверов занимаем заранее: теги вариантов строятся из них
	// и не должны совпасть с соседним сервером.
	var tags []string
	for _, s := range in.Servers {
		tags = append(tags, unique(s.Name))
	}
	var out []any
	for i, s := range in.Servers {
		obs, err := serverOutbounds(s, tags[i], unique)
		if err != nil {
			return nil, err
		}
		out = append(out, obs...)
	}
	selected := TagAuto
	if sub := in.Profile.Subscription; sub != nil && sub.Server != "" {
		for _, t := range tags {
			if t == sub.Server {
				selected = t
			}
		}
	}
	out = append(out,
		urlTest(TagAuto, tags),
		M{
			"type":      "selector",
			"tag":       TagProxy,
			"outbounds": append([]string{TagAuto}, tags...),
			"default":   selected,
			// При ручной смене сервера рвём старые соединения, чтобы они
			// сразу переподключились через новый.
			"interrupt_exist_connections": true,
		},
	)
	return out, nil
}

// serverOutbounds собирает outbound'ы одного сервера под тегом tag: сам
// outbound или urltest по его вариантам.
func serverOutbounds(s subscription.Server, tag string, unique func(string) string) ([]any, error) {
	if len(s.Links) == 1 {
		ob, err := linkOutbound(s.Links[0], tag)
		if err != nil && s.Name != "" {
			err = fmt.Errorf("сервер %q: %w", s.Name, err)
		}
		if err != nil {
			return nil, err
		}
		return []any{ob}, nil
	}
	var out []any
	var variants []string
	for _, l := range s.Links {
		vtag := unique(strings.TrimSpace(tag) + " / " + l.Name)
		ob, err := linkOutbound(l, vtag)
		if err != nil {
			return nil, fmt.Errorf("сервер %q (%s): %w", s.Name, l.Name, err)
		}
		out = append(out, ob)
		variants = append(variants, vtag)
	}
	return append(out, urlTest(tag, variants)), nil
}

func urlTest(tag string, outbounds []string) M {
	return M{
		"type":      "urltest",
		"tag":       tag,
		"outbounds": outbounds,
		"url":       URLTestURL,
		"interval":  "5m",
		"tolerance": 50,
	}
}

func linkOutbound(l *vless.Link, tag string) (M, error) {
	if l.Protocol == "hysteria2" {
		return hysteria2Outbound(l, tag), nil
	}
	return vlessOutbound(l, tag)
}

func hysteria2Outbound(l *vless.Link, tag string) M {
	ob := M{
		"type":        "hysteria2",
		"tag":         tag,
		"server":      l.Server,
		"server_port": l.Port,
		"password":    l.Password,
	}
	if len(l.ServerPorts) > 0 {
		ob["server_ports"] = l.ServerPorts
	}
	if l.Obfs != "" {
		ob["obfs"] = M{"type": l.Obfs, "password": l.ObfsPassword}
	}
	tls := M{"enabled": true}
	if l.SNI != "" {
		tls["server_name"] = l.SNI
	}
	if l.Insecure {
		tls["insecure"] = true
	}
	if len(l.ALPN) > 0 {
		tls["alpn"] = l.ALPN
	}
	ob["tls"] = tls
	return ob
}

func vlessOutbound(l *vless.Link, tag string) (M, error) {
	ob := M{
		"type":            "vless",
		"tag":             tag,
		"server":          l.Server,
		"server_port":     l.Port,
		"uuid":            l.UUID,
		"packet_encoding": "xudp",
	}
	if l.Flow != "" {
		ob["flow"] = l.Flow
	}
	if l.PacketEncoding != "" {
		ob["packet_encoding"] = l.PacketEncoding
	}

	if l.Security != "none" {
		tls := M{"enabled": true}
		if l.SNI != "" {
			tls["server_name"] = l.SNI
		}
		if l.Insecure {
			tls["insecure"] = true
		}
		if len(l.ALPN) > 0 {
			tls["alpn"] = l.ALPN
		}
		fp := l.Fingerprint
		if fp == "" && l.Security == "reality" {
			// Reality в sing-box работает только через uTLS.
			fp = "chrome"
		}
		if fp != "" {
			tls["utls"] = M{"enabled": true, "fingerprint": fp}
		}
		if l.Security == "reality" {
			reality := M{"enabled": true, "public_key": l.PublicKey}
			if l.ShortID != "" {
				reality["short_id"] = l.ShortID
			}
			tls["reality"] = reality
		}
		ob["tls"] = tls
	}

	switch l.Transport {
	case "tcp":
	case "ws":
		t := M{"type": "ws"}
		path, earlyData := splitEarlyData(l.Path)
		if path != "" {
			t["path"] = path
		}
		if earlyData > 0 {
			t["max_early_data"] = earlyData
			t["early_data_header_name"] = "Sec-WebSocket-Protocol"
		}
		if l.Host != "" {
			t["headers"] = M{"Host": l.Host}
		}
		ob["transport"] = t
	case "grpc":
		t := M{"type": "grpc"}
		if l.ServiceName != "" {
			t["service_name"] = l.ServiceName
		}
		ob["transport"] = t
	case "http":
		t := M{"type": "http"}
		if l.Host != "" {
			t["host"] = strings.Split(l.Host, ",")
		}
		if l.Path != "" {
			t["path"] = l.Path
		}
		ob["transport"] = t
	case "httpupgrade":
		t := M{"type": "httpupgrade"}
		if l.Host != "" {
			t["host"] = l.Host
		}
		if l.Path != "" {
			t["path"] = l.Path
		}
		ob["transport"] = t
	default:
		return nil, fmt.Errorf("vless: транспорт %q не поддерживается", l.Transport)
	}
	return ob, nil
}

// splitEarlyData вынимает параметр ?ed=N из пути WebSocket (формат Xray).
func splitEarlyData(path string) (string, int) {
	base, query, ok := strings.Cut(path, "?")
	if !ok {
		return path, 0
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return path, 0
	}
	ed, err := strconv.Atoi(values.Get("ed"))
	if err != nil || ed <= 0 {
		return path, 0
	}
	values.Del("ed")
	if rest := values.Encode(); rest != "" {
		base += "?" + rest
	}
	return base, ed
}

// Опции, которые сервер не должен навязывать: весь трафик через OpenVPN
// и блокировку DNS на остальных интерфейсах.
var forcedPullFilters = []ovpn.PullFilter{
	{Action: "ignore", Text: "redirect-gateway"},
	{Action: "ignore", Text: "block-outside-dns"},
}

func openVPNEndpoint(c *ovpn.Config, p *profile.Profile) (M, error) {
	ep := M{
		"type":    "openvpn-client",
		"tag":     TagCorp,
		"network": c.Proto,
	}

	var servers []any
	for _, r := range c.Remotes {
		port := r.Port
		if port == 0 {
			port = c.Port
		}
		s := M{"server": r.Host, "server_port": port}
		if r.Proto != "" && r.Proto != c.Proto {
			s["network"] = r.Proto
		}
		servers = append(servers, s)
	}
	ep["servers"] = servers
	if c.RemoteRandom {
		ep["remote_random"] = true
	}

	username, password := c.Username, c.Password
	if p.OpenVPN.Username != "" {
		username = p.OpenVPN.Username
	}
	if p.OpenVPN.Password != "" {
		password = p.OpenVPN.Password
	}
	if c.AuthUserPass {
		if username == "" {
			return nil, fmt.Errorf("openvpn: сервер требует логин и пароль, укажите openvpn.username и openvpn.password в профиле")
		}
		ep["username"] = username
		ep["password"] = password
	}
	if c.AuthRetry != "" {
		ep["auth_retry"] = c.AuthRetry
	}
	if c.StaticChallenge != "" {
		ep["static_challenge"] = c.StaticChallenge
		ep["static_challenge_echo"] = c.StaticChallengeEcho
	}

	tls := M{}
	if c.CA != "" {
		tls["certificate"] = c.CA
	}
	if c.Cert != "" {
		tls["client_certificate"] = c.Cert
		tls["client_key"] = c.Key
	}
	if len(c.PeerFingerprints) > 0 {
		tls["peer_fingerprint"] = c.PeerFingerprints
	}
	if c.CRLPath != "" {
		tls["crl_path"] = c.CRLPath
	}
	if c.VerifyX509Name != "" {
		tls["server_name"] = c.VerifyX509Name
		tls["server_name_type"] = c.VerifyX509Type
	}
	switch {
	case c.RemoteCertEKU != "":
		tls["remote_certificate_eku"] = c.RemoteCertEKU
	case c.RemoteCertTLS != "":
		tls["remote_certificate_tls"] = c.RemoteCertTLS
	case c.NSCertType != "":
		// ns-cert-type без remote-cert-tls: не включаем дефолтную проверку EKU,
		// которой старые сертификаты могут не соответствовать.
		tls["ns_certificate_type"] = c.NSCertType
		tls["remote_certificate_tls"] = "none"
	}
	if len(c.RemoteCertKU) > 0 {
		tls["remote_certificate_ku"] = c.RemoteCertKU
	}
	if c.TLSVersionMin != "" {
		tls["version_min"] = c.TLSVersionMin
	}
	if c.TLSVersionMax != "" {
		tls["version_max"] = c.TLSVersionMax
	}
	if c.TLSCipher != "" {
		tls["cipher"] = c.TLSCipher
	}
	if c.TLSGroups != "" {
		tls["groups"] = c.TLSGroups
	}
	switch {
	case c.TLSCryptV2 != "":
		tls["control_wrap"] = M{"type": "tls_crypt_v2", "key": c.TLSCryptV2}
	case c.TLSCrypt != "":
		tls["control_wrap"] = M{"type": "tls_crypt", "key": c.TLSCrypt}
	case c.TLSAuth != "":
		wrap := M{"type": "tls_auth", "key": c.TLSAuth}
		if c.KeyDirection != "" {
			wrap["direction"] = c.KeyDirection
		}
		tls["control_wrap"] = wrap
	}
	ep["tls"] = tls

	if len(c.DataCiphers) > 0 {
		ep["data_ciphers"] = c.DataCiphers
	}
	fallback := c.DataCiphersFallback
	if fallback == "" && c.Cipher != "" {
		// В OpenVPN 2.6 директива cipher на клиенте означает запасной шифр
		// для серверов без согласования шифров.
		fallback = c.Cipher
	}
	if fallback != "" {
		ep["data_ciphers_fallback"] = fallback
	}
	if c.Auth != "" {
		ep["auth"] = c.Auth
	}
	if c.CompLZO != "" {
		ep["compression_lzo"] = c.CompLZO
	}
	if c.Compress != "" {
		ep["compression"] = c.Compress
	}
	if c.AllowCompression != "" {
		ep["allow_compression"] = c.AllowCompression
	}

	if c.TunMTU != 0 {
		ep["mtu"] = c.TunMTU
	}
	if c.MSSFixDisabled {
		ep["mss_fix_disabled"] = true
	} else if c.MSSFix != 0 {
		ep["mss_fix"] = c.MSSFix
	}
	if c.Fragment != 0 {
		ep["fragment"] = c.Fragment
	}
	if c.PingInterval > 0 {
		ep["ping_interval"] = seconds(c.PingInterval)
	}
	if c.PingRestart > 0 {
		ep["ping_restart"] = seconds(c.PingRestart)
	}
	if c.RenegDisabled {
		ep["renegotiate_disabled"] = true
	} else if c.RenegSec > 0 {
		ep["renegotiate_interval"] = seconds(c.RenegSec)
	}
	if c.RenegBytes > 0 {
		ep["renegotiate_bytes"] = c.RenegBytes
	}
	if c.RenegPackets > 0 {
		ep["renegotiate_packets"] = c.RenegPackets
	}
	if c.HandWindow > 0 {
		ep["handshake_window"] = seconds(c.HandWindow)
	}
	if c.TLSTimeout > 0 {
		ep["tls_timeout"] = seconds(c.TLSTimeout)
	}
	if c.ReplayWindow > 0 {
		ep["replay_window"] = c.ReplayWindow
	}
	if c.ReplayWindowTime > 0 {
		ep["replay_window_time"] = seconds(c.ReplayWindowTime)
	}
	if c.ExplicitExitNotify > 0 && strings.HasPrefix(c.Proto, "udp") {
		ep["explicit_exit_notify"] = c.ExplicitExitNotify
	}

	if c.RouteNoPull {
		ep["route_no_pull"] = true
	}
	var filters []any
	for _, f := range append(append([]ovpn.PullFilter{}, forcedPullFilters...), c.PullFilters...) {
		filters = append(filters, M{"action": f.Action, "text": f.Text})
	}
	ep["pull_filters"] = filters
	if len(c.Routes) > 0 {
		routes := make([]string, 0, len(c.Routes))
		for _, r := range c.Routes {
			routes = append(routes, r.String())
		}
		ep["routes"] = routes
	}
	if c.BlockIPv6 {
		ep["block_ipv6"] = true
	}
	return ep, nil
}

func seconds(n int) string {
	return strconv.Itoa(n) + "s"
}
