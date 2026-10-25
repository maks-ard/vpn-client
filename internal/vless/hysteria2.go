package vless

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ParseLink разбирает ссылку на сервер любого поддерживаемого протокола.
func ParseLink(raw string) (*Link, error) {
	raw = strings.TrimSpace(raw)
	scheme, _, _ := strings.Cut(raw, "://")
	switch strings.ToLower(scheme) {
	case "hysteria2", "hy2":
		return ParseHysteria2(raw)
	}
	return Parse(raw)
}

// ParseHysteria2 разбирает ссылку hysteria2://пароль@хост:порт/?sni=…#имя
// (формат официального клиента Hysteria и панелей). Порт может быть списком
// для смены портов: 443,20000-30000.
func ParseHysteria2(raw string) (*Link, error) {
	raw = strings.TrimSpace(raw)
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || (!strings.EqualFold(scheme, "hysteria2") && !strings.EqualFold(scheme, "hy2")) {
		return nil, fmt.Errorf("ожидается ссылка hysteria2://, получено %q", scheme+"://")
	}
	// Список портов url.Parse не принимает, поэтому адрес разбираем сами,
	// а url.Parse отдаём ссылку с одним хостом.
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	userinfo, hostport := "", authority
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		userinfo, hostport = authority[:i+1], authority[i+1:]
	}
	host, ports := hostport, ""
	if i := strings.LastIndex(hostport, ":"); i >= 0 && !strings.HasSuffix(hostport, "]") {
		host, ports = hostport[:i], hostport[i+1:]
	}
	u, err := url.Parse("hysteria2://" + userinfo + host + tail)
	if err != nil {
		return nil, fmt.Errorf("неверная ссылка Hysteria2: %w", err)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("в ссылке нет адреса сервера")
	}
	// Вариант userpass официального клиента sing-box понимает только как
	// пароль «логин:пароль».
	password := ""
	if u.User != nil {
		password = u.User.Username()
		if p, ok := u.User.Password(); ok {
			password += ":" + p
		}
	}
	if password == "" {
		return nil, fmt.Errorf("в ссылке нет пароля")
	}

	q := u.Query()
	l := &Link{
		Protocol:     "hysteria2",
		Name:         u.Fragment,
		Server:       u.Hostname(),
		Password:     password,
		Security:     "tls",
		SNI:          q.Get("sni"),
		Obfs:         strings.ToLower(q.Get("obfs")),
		ObfsPassword: q.Get("obfs-password"),
	}
	if ports == "" {
		ports = "443"
	}
	// mport — так диапазон для смены портов передают v2rayN и некоторые панели.
	if mport := q.Get("mport"); mport != "" {
		ports += "," + mport
	}
	if l.Port, l.ServerPorts, err = parsePorts(ports); err != nil {
		return nil, err
	}
	switch strings.ToLower(q.Get("insecure")) {
	case "1", "true":
		l.Insecure = true
	}
	if alpn := q.Get("alpn"); alpn != "" {
		l.ALPN = strings.Split(alpn, ",")
	}
	switch l.Obfs {
	case "", "none":
		l.Obfs = ""
	case "salamander", "gecko":
		if l.ObfsPassword == "" {
			return nil, fmt.Errorf("для обфускации %s нужен obfs-password", l.Obfs)
		}
	default:
		return nil, fmt.Errorf("обфускация %q не поддерживается", l.Obfs)
	}
	if l.SNI == "" && net.ParseIP(l.Server) == nil {
		l.SNI = l.Server
	}
	return l, nil
}

// parsePorts разбирает «443» или «443,20000-30000». Один порт — обычное
// подключение; несколько — смена портов, диапазоны в формате sing-box «a:b».
func parsePorts(s string) (uint16, []string, error) {
	parse := func(p string) (uint16, error) {
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 16)
		if err != nil || n == 0 {
			return 0, fmt.Errorf("неверный порт %q", p)
		}
		return uint16(n), nil
	}
	parts := strings.Split(s, ",")
	var first uint16
	var ranges []string
	for _, part := range parts {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := parse(lo)
		if err != nil {
			return 0, nil, err
		}
		b := a
		if isRange {
			if b, err = parse(hi); err != nil {
				return 0, nil, err
			}
			if b < a {
				return 0, nil, fmt.Errorf("неверный диапазон портов %q", part)
			}
		}
		if first == 0 {
			first = a
		}
		ranges = append(ranges, fmt.Sprintf("%d:%d", a, b))
	}
	if len(parts) == 1 && !strings.Contains(s, "-") {
		return first, nil, nil
	}
	return first, ranges, nil
}
