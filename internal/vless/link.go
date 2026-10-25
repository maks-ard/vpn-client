// Package vless разбирает ссылки на серверы, которые выдают панели 3x-ui,
// Marzban, Remnawave и т.п.: vless://uuid@host:port?...#name и hysteria2://.
package vless

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Link struct {
	// Protocol: "" (VLESS) или "hysteria2".
	Protocol string

	Name   string
	UUID   string
	Server string
	Port   uint16
	Flow   string

	// Security: "none", "tls" или "reality".
	Security    string
	SNI         string
	Fingerprint string
	ALPN        []string
	Insecure    bool
	PublicKey   string
	ShortID     string

	// Transport: "tcp", "ws", "grpc", "http", "httpupgrade".
	Transport   string
	Path        string
	Host        string
	ServiceName string

	PacketEncoding string

	// Поля Hysteria2. ServerPorts — диапазоны для смены портов («a:b»).
	Password     string
	ServerPorts  []string
	Obfs         string
	ObfsPassword string
}

func Parse(raw string) (*Link, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("неверная ссылка VLESS: %w", err)
	}
	if u.Scheme != "vless" {
		return nil, fmt.Errorf("ожидается ссылка vless://, получено %q", u.Scheme+"://")
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("в ссылке нет UUID")
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("в ссылке нет адреса сервера")
	}
	portStr := u.Port()
	if portStr == "" {
		portStr = "443"
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("неверный порт %q", portStr)
	}

	q := u.Query()
	l := &Link{
		Name:           u.Fragment,
		UUID:           u.User.Username(),
		Server:         host,
		Port:           uint16(port),
		Flow:           q.Get("flow"),
		Security:       strings.ToLower(q.Get("security")),
		SNI:            q.Get("sni"),
		Fingerprint:    q.Get("fp"),
		PublicKey:      q.Get("pbk"),
		ShortID:        q.Get("sid"),
		Transport:      strings.ToLower(q.Get("type")),
		Path:           q.Get("path"),
		Host:           q.Get("host"),
		ServiceName:    q.Get("serviceName"),
		PacketEncoding: q.Get("packetEncoding"),
	}
	if enc := q.Get("encryption"); enc != "" && enc != "none" {
		return nil, fmt.Errorf("шифрование VLESS %q не поддерживается sing-box", enc)
	}
	if alpn := q.Get("alpn"); alpn != "" {
		l.ALPN = strings.Split(alpn, ",")
	}
	switch strings.ToLower(q.Get("allowInsecure")) {
	case "1", "true":
		l.Insecure = true
	}
	if l.SNI == "" {
		l.SNI = q.Get("peer")
	}

	switch l.Security {
	case "", "none":
		l.Security = "none"
	case "tls", "xtls":
		l.Security = "tls"
	case "reality":
		if l.PublicKey == "" {
			return nil, fmt.Errorf("для Reality нужен публичный ключ (pbk)")
		}
	default:
		return nil, fmt.Errorf("неподдерживаемый security=%q", l.Security)
	}
	if l.Security != "none" && l.SNI == "" && net.ParseIP(host) == nil {
		l.SNI = host
	}

	switch l.Transport {
	case "", "tcp", "raw":
		l.Transport = "tcp"
		if ht := q.Get("headerType"); ht == "http" {
			// tcp + http-маскировка в sing-box — это HTTP-транспорт без TLS-обязательств
			l.Transport = "http"
		}
	case "ws", "grpc", "httpupgrade":
	case "http", "h2":
		l.Transport = "http"
	case "xhttp", "splithttp":
		return nil, fmt.Errorf("транспорт XHTTP не поддерживается sing-box")
	case "kcp", "mkcp", "quic":
		return nil, fmt.Errorf("транспорт %q не поддерживается", l.Transport)
	default:
		return nil, fmt.Errorf("неизвестный транспорт %q", l.Transport)
	}

	if l.Flow != "" && l.Flow != "xtls-rprx-vision" {
		return nil, fmt.Errorf("flow %q не поддерживается (только xtls-rprx-vision)", l.Flow)
	}
	if l.Flow != "" && l.Transport != "tcp" {
		return nil, fmt.Errorf("flow xtls-rprx-vision работает только с транспортом tcp")
	}
	return l, nil
}
