// Package profile описывает пользовательский профиль: какие серверы
// использовать и как разводить трафик.
package profile

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Profile struct {
	// VLESS — ссылка vless://… для зарубежного трафика.
	VLESS string `yaml:"vless"`
	// Subscription — подписка со списком серверов (вместо одной ссылки vless).
	Subscription *Subscription `yaml:"subscription"`

	OpenVPN   *OpenVPN  `yaml:"openvpn"`
	Corporate Corporate `yaml:"corporate"`
	Routing   Routing   `yaml:"routing"`
	DNS       DNS       `yaml:"dns"`
	TUN       TUN       `yaml:"tun"`
	SingBox   SingBox   `yaml:"singbox"`

	// dir — каталог файла профиля, от него считаются относительные пути.
	dir string
}

type Subscription struct {
	// URL — https-ссылка подписки из панели (Remnawave, Marzban, 3x-ui…).
	URL string `yaml:"url"`
	// UserAgent — с каким User-Agent запрашивать; по умолчанию как v2rayN.
	UserAgent string `yaml:"user_agent"`
	// Server — имя выбранного сервера; пусто — самый быстрый автоматически.
	Server string `yaml:"server"`
}

type OpenVPN struct {
	// Config — путь к .ovpn.
	Config   string `yaml:"config"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Corporate struct {
	// Domains — домены (вместе с поддоменами), которые идут через OpenVPN.
	Domains []string `yaml:"domains"`
	// Subnets — подсети, которые идут через OpenVPN в дополнение к маршрутам,
	// присланным сервером.
	Subnets []string `yaml:"subnets"`
}

type Routing struct {
	// RussiaDirect — российские сайты и IP напрямую, остальное через VLESS.
	// Если false, через VLESS идёт всё, кроме корпоративного и direct_domains.
	RussiaDirect *bool `yaml:"russia_direct"`
	// DirectDomains — всегда напрямую.
	DirectDomains []string `yaml:"direct_domains"`
	// ProxyDomains — всегда через VLESS (приоритетнее правил для России).
	ProxyDomains []string `yaml:"proxy_domains"`
	// DirectProcesses — программы, чей трафик идёт напрямую (например, торрент-клиент).
	DirectProcesses []string `yaml:"direct_processes"`
}

type DNS struct {
	// Direct — DNS для российских доменов, ходит напрямую.
	Direct string `yaml:"direct"`
	// Remote — DNS-over-HTTPS для остальных доменов, ходит через VLESS.
	Remote string `yaml:"remote"`
}

type TUN struct {
	// Stack — system, gvisor или mixed.
	Stack string `yaml:"stack"`
	MTU   uint32 `yaml:"mtu"`
	IPv6  bool   `yaml:"ipv6"`
}

type SingBox struct {
	// Path — путь к sing-box.exe; по умолчанию рядом с vpnclient.exe.
	Path     string `yaml:"path"`
	LogLevel string `yaml:"log_level"`
	// ClashAPI — адрес Clash API для статистики и дашборда, например 127.0.0.1:9090.
	ClashAPI string `yaml:"clash_api"`
}

func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data, filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

func Parse(data []byte, dir string) (*Profile, error) {
	p := &Profile{dir: dir}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(p); err != nil {
		return nil, err
	}
	p.applyDefaults()
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// Resolve возвращает путь относительно каталога профиля.
func (p *Profile) Resolve(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(p.dir, path)
}

func (p *Profile) RussiaDirect() bool {
	return p.Routing.RussiaDirect == nil || *p.Routing.RussiaDirect
}

func (p *Profile) applyDefaults() {
	if p.DNS.Direct == "" {
		p.DNS.Direct = "77.88.8.8"
	}
	if p.DNS.Remote == "" {
		p.DNS.Remote = "1.1.1.1"
	}
	if p.TUN.Stack == "" {
		p.TUN.Stack = "mixed"
	}
	if p.TUN.MTU == 0 {
		p.TUN.MTU = 9000
	}
	if p.SingBox.LogLevel == "" {
		p.SingBox.LogLevel = "warn"
	}
	p.Corporate.Domains = normalizeDomains(p.Corporate.Domains)
	p.Routing.DirectDomains = normalizeDomains(p.Routing.DirectDomains)
	p.Routing.ProxyDomains = normalizeDomains(p.Routing.ProxyDomains)
}

func (p *Profile) validate() error {
	if p.Subscription != nil && p.Subscription.URL == "" {
		p.Subscription = nil
	}
	if p.VLESS == "" && p.Subscription == nil && p.OpenVPN == nil {
		return fmt.Errorf("нужен хотя бы один из разделов: subscription, vless или openvpn")
	}
	if p.VLESS != "" && p.Subscription != nil {
		return fmt.Errorf("укажите что-то одно: subscription или vless")
	}
	if p.Subscription != nil && !strings.HasPrefix(p.Subscription.URL, "https://") && !strings.HasPrefix(p.Subscription.URL, "http://") {
		return fmt.Errorf("subscription.url: ожидается ссылка https://")
	}
	if p.OpenVPN != nil && p.OpenVPN.Config == "" {
		return fmt.Errorf("openvpn.config: укажите путь к .ovpn")
	}
	if p.OpenVPN == nil && (len(p.Corporate.Domains) > 0 || len(p.Corporate.Subnets) > 0) {
		return fmt.Errorf("corporate задан, но нет раздела openvpn")
	}
	for _, s := range p.Corporate.Subnets {
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("corporate.subnets: %w", err)
		}
	}
	switch p.TUN.Stack {
	case "system", "gvisor", "mixed":
	default:
		return fmt.Errorf("tun.stack: ожидается system, gvisor или mixed")
	}
	switch p.SingBox.LogLevel {
	case "trace", "debug", "info", "warn", "error", "fatal", "panic":
	default:
		return fmt.Errorf("singbox.log_level: неизвестный уровень %q", p.SingBox.LogLevel)
	}
	return nil
}

func normalizeDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, "*.")
		d = strings.Trim(d, ".")
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}
