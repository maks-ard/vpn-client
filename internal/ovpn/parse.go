// Package ovpn разбирает клиентские конфиги OpenVPN (.ovpn) в структуру,
// которую затем можно перевести в endpoint `openvpn-client` sing-box.
package ovpn

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Remote struct {
	Host  string
	Port  uint16
	Proto string // "udp" | "tcp" | "" (значит, берётся общий proto)
}

type PullFilter struct {
	Action string // accept | ignore | reject
	Text   string
}

type Config struct {
	Remotes      []Remote
	RemoteRandom bool
	Proto        string // udp | tcp
	Port         uint16

	CA         string
	Cert       string
	Key        string
	CRLPath    string
	TLSAuth    string
	TLSCrypt   string
	TLSCryptV2 string
	// KeyDirection — "server" или "client" в терминах sing-box (0 и 1 в OpenVPN).
	KeyDirection string

	AuthUserPass bool
	Username     string
	Password     string
	AuthRetry    string

	StaticChallenge     string
	StaticChallengeEcho bool

	Cipher              string
	DataCiphers         []string
	DataCiphersFallback string
	Auth                string
	CompLZO             string
	Compress            string
	AllowCompression    string

	RemoteCertTLS    string
	RemoteCertKU     []string
	RemoteCertEKU    string
	NSCertType       string
	VerifyX509Name   string
	VerifyX509Type   string // subject | name | name-prefix
	TLSVersionMin    string
	TLSVersionMax    string
	TLSCipher        string
	TLSGroups        string
	PeerFingerprints []string

	TunMTU         uint32
	MSSFix         uint32
	MSSFixDisabled bool
	Fragment       uint32

	PingInterval     int
	PingRestart      int
	RenegSec         int
	RenegDisabled    bool
	RenegBytes       uint64
	RenegPackets     uint64
	HandWindow       int
	TLSTimeout       int
	ReplayWindow     uint32
	ReplayWindowTime int

	RouteNoPull          bool
	PullFilters          []PullFilter
	Routes               []netip.Prefix
	RedirectGateway      bool
	RedirectGatewayFlags []string
	BlockIPv6            bool

	ExplicitExitNotify uint32

	// Warnings — директивы, которые проигнорированы или поддержаны частично.
	Warnings []string
}

// ParseFile читает .ovpn с диска. Пути к ca/cert/key и т.п. считаются
// относительно каталога самого файла.
func ParseFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, err := Parse(f, filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse разбирает конфиг из r. baseDir нужен для директив, ссылающихся на файлы.
func Parse(r io.Reader, baseDir string) (*Config, error) {
	p := &parser{cfg: &Config{Proto: "udp", Port: 1194}, baseDir: baseDir}
	if err := p.run(r); err != nil {
		return nil, err
	}
	return p.finish()
}

type parser struct {
	cfg     *Config
	baseDir string
	line    int
	// tls-auth/key-direction могут идти в любом порядке
	tlsAuthDirection string
}

// Директивы, которые не влияют на userspace-клиент или берутся sing-box на себя.
var ignored = map[string]bool{
	"client": true, "tls-client": true, "pull": true, "nobind": true,
	"persist-key": true, "persist-tun": true, "persist-remote-ip": true,
	"resolv-retry": true, "verb": true, "mute": true, "mute-replay-warnings": true,
	"auth-nocache": true, "float": true, "sndbuf": true, "rcvbuf": true,
	"connect-retry": true, "connect-retry-max": true, "connect-timeout": true,
	"server-poll-timeout": true, "dev-type": true, "dev-node": true,
	"windows-driver": true, "route-method": true, "route-delay": true,
	"register-dns": true, "block-outside-dns": true, "dhcp-option": true,
	"setenv": true, "setenv-safe": true, "push-peer-info": true,
	"ignore-unknown-option": true, "script-security": true, "up": true,
	"down": true, "route-up": true, "ip-win32": true, "tap-sleep": true,
	"auth-token": true, "auth-token-user": true, "remote-cert-tls-legacy": true,
	"txqueuelen": true, "fast-io": true, "lport": true, "bind": true,
	"user": true, "group": true, "chroot": true, "daemon": true,
	"keepalive-timeout": true, "data-ciphers-fallback-auto": true,
	"route-metric": true, "allow-pull-fqdn": true, "machine-readable-output": true,
	"providers": true, "disable-dco": true, "tun-mtu-extra": true,
	"key-method": true, "ncp-disable": true, "management": true,
	"management-hold": true, "management-query-passwords": true, "log": true,
	"log-append": true, "status": true, "writepid": true, "inactive": true,
	"auth-user-pass-verify": true, "tls-exit": true, "single-session": true,
}

func (p *parser) run(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var blockName string
	var block strings.Builder
	for sc.Scan() {
		p.line++
		raw := strings.TrimRight(sc.Text(), "\r")
		if p.line == 1 {
			raw = strings.TrimPrefix(raw, "\uFEFF")
		}
		if blockName != "" {
			if strings.TrimSpace(raw) == "</"+blockName+">" {
				if err := p.inline(blockName, block.String()); err != nil {
					return p.errorf("<%s>: %v", blockName, err)
				}
				blockName = ""
				block.Reset()
				continue
			}
			block.WriteString(raw)
			block.WriteByte('\n')
			continue
		}
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			blockName = line[1 : len(line)-1]
			continue
		}
		args, err := splitArgs(line)
		if err != nil {
			return p.errorf("%v", err)
		}
		if len(args) == 0 {
			continue
		}
		name := strings.TrimPrefix(args[0], "--")
		if err := p.directive(name, args[1:]); err != nil {
			return p.errorf("%s: %v", name, err)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if blockName != "" {
		return fmt.Errorf("незакрытый блок <%s>", blockName)
	}
	return nil
}

func (p *parser) errorf(format string, a ...any) error {
	return fmt.Errorf("строка %d: %s", p.line, fmt.Sprintf(format, a...))
}

func (p *parser) warn(format string, a ...any) {
	p.cfg.Warnings = append(p.cfg.Warnings, fmt.Sprintf("строка %d: ", p.line)+fmt.Sprintf(format, a...))
}

func (p *parser) inline(name, content string) error {
	c := p.cfg
	switch name {
	case "ca":
		c.CA = content
	case "cert":
		c.Cert = content
	case "key":
		c.Key = content
	case "tls-auth":
		c.TLSAuth = content
	case "tls-crypt":
		c.TLSCrypt = content
	case "tls-crypt-v2":
		c.TLSCryptV2 = content
	case "auth-user-pass":
		c.AuthUserPass = true
		return p.setCredentials(content)
	case "peer-fingerprint":
		for _, l := range strings.Split(content, "\n") {
			if l = strings.TrimSpace(l); l != "" && l[0] != '#' {
				c.PeerFingerprints = append(c.PeerFingerprints, normalizeFingerprint(l))
			}
		}
	case "connection":
		return fmt.Errorf("блоки <connection> пока не поддерживаются, вынесите remote в основной конфиг")
	case "pkcs12":
		return fmt.Errorf("PKCS#12 не поддерживается, сконвертируйте в PEM (ca/cert/key)")
	case "dh", "extra-certs", "http-proxy-user-pass":
		p.warn("блок <%s> проигнорирован", name)
	default:
		p.warn("неизвестный блок <%s> проигнорирован", name)
	}
	return nil
}

func (p *parser) directive(name string, args []string) error {
	c := p.cfg
	switch name {
	case "remote":
		if len(args) < 1 {
			return fmt.Errorf("нужен адрес сервера")
		}
		rm := Remote{Host: args[0]}
		if len(args) > 1 {
			port, err := parsePort(args[1])
			if err != nil {
				return err
			}
			rm.Port = port
		}
		if len(args) > 2 {
			proto, err := normalizeProto(args[2])
			if err != nil {
				return err
			}
			rm.Proto = proto
		}
		c.Remotes = append(c.Remotes, rm)
	case "remote-random":
		c.RemoteRandom = true
	case "proto":
		if err := need(args, 1); err != nil {
			return err
		}
		proto, err := normalizeProto(args[0])
		if err != nil {
			return err
		}
		c.Proto = proto
	case "port", "rport":
		if err := need(args, 1); err != nil {
			return err
		}
		port, err := parsePort(args[0])
		if err != nil {
			return err
		}
		c.Port = port
	case "dev":
		if err := need(args, 1); err != nil {
			return err
		}
		if !strings.HasPrefix(args[0], "tun") {
			return fmt.Errorf("поддерживается только dev tun, а не %q", args[0])
		}
	case "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2":
		if err := need(args, 1); err != nil {
			return err
		}
		if args[0] == "[inline]" {
			if name == "tls-auth" && len(args) > 1 {
				p.tlsAuthDirection = args[1]
			}
			return nil
		}
		content, err := p.readFile(args[0])
		if err != nil {
			return err
		}
		if err := p.inline(name, content); err != nil {
			return err
		}
		if name == "tls-auth" && len(args) > 1 {
			p.tlsAuthDirection = args[1]
		}
	case "key-direction":
		if err := need(args, 1); err != nil {
			return err
		}
		p.tlsAuthDirection = args[0]
	case "crl-verify":
		if err := need(args, 1); err != nil {
			return err
		}
		if len(args) > 1 && args[1] == "dir" {
			return fmt.Errorf("crl-verify dir не поддерживается")
		}
		c.CRLPath = p.resolve(args[0])
	case "auth-user-pass":
		c.AuthUserPass = true
		if len(args) > 0 {
			content, err := p.readFile(args[0])
			if err != nil {
				return err
			}
			return p.setCredentials(content)
		}
	case "auth-retry":
		if err := need(args, 1); err != nil {
			return err
		}
		c.AuthRetry = args[0]
	case "static-challenge":
		if err := need(args, 1); err != nil {
			return err
		}
		c.StaticChallenge = args[0]
		c.StaticChallengeEcho = len(args) > 1 && args[1] == "1"
	case "cipher":
		if err := need(args, 1); err != nil {
			return err
		}
		c.Cipher = args[0]
	case "data-ciphers", "ncp-ciphers":
		if err := need(args, 1); err != nil {
			return err
		}
		c.DataCiphers = strings.Split(args[0], ":")
	case "data-ciphers-fallback":
		if err := need(args, 1); err != nil {
			return err
		}
		c.DataCiphersFallback = args[0]
	case "auth":
		if err := need(args, 1); err != nil {
			return err
		}
		c.Auth = args[0]
	case "comp-lzo":
		c.CompLZO = "adaptive"
		if len(args) > 0 {
			c.CompLZO = args[0]
		}
	case "compress":
		c.Compress = "stub"
		if len(args) > 0 {
			c.Compress = args[0]
		}
	case "allow-compression":
		if err := need(args, 1); err != nil {
			return err
		}
		c.AllowCompression = args[0]
	case "remote-cert-tls":
		if err := need(args, 1); err != nil {
			return err
		}
		c.RemoteCertTLS = args[0]
	case "remote-cert-ku":
		c.RemoteCertKU = append(c.RemoteCertKU, args...)
	case "remote-cert-eku":
		if err := need(args, 1); err != nil {
			return err
		}
		c.RemoteCertEKU = args[0]
	case "ns-cert-type":
		if err := need(args, 1); err != nil {
			return err
		}
		c.NSCertType = args[0]
	case "verify-x509-name":
		if err := need(args, 1); err != nil {
			return err
		}
		c.VerifyX509Name = args[0]
		c.VerifyX509Type = "subject"
		if len(args) > 1 {
			c.VerifyX509Type = args[1]
		}
		switch c.VerifyX509Type {
		case "subject", "name", "name-prefix":
		default:
			return fmt.Errorf("неизвестный тип %q", c.VerifyX509Type)
		}
	case "tls-version-min":
		if err := need(args, 1); err != nil {
			return err
		}
		c.TLSVersionMin = args[0]
	case "tls-version-max":
		if err := need(args, 1); err != nil {
			return err
		}
		c.TLSVersionMax = args[0]
	case "tls-cipher":
		if err := need(args, 1); err != nil {
			return err
		}
		c.TLSCipher = args[0]
	case "tls-groups":
		if err := need(args, 1); err != nil {
			return err
		}
		c.TLSGroups = args[0]
	case "peer-fingerprint":
		if err := need(args, 1); err != nil {
			return err
		}
		c.PeerFingerprints = append(c.PeerFingerprints, normalizeFingerprint(args[0]))
	case "tun-mtu":
		v, err := parseUint(args, 32)
		if err != nil {
			return err
		}
		c.TunMTU = uint32(v)
	case "mssfix":
		if len(args) == 0 {
			return nil
		}
		v, err := parseUint(args, 32)
		if err != nil {
			return err
		}
		if v == 0 {
			c.MSSFixDisabled = true
		} else {
			c.MSSFix = uint32(v)
		}
	case "fragment":
		v, err := parseUint(args, 32)
		if err != nil {
			return err
		}
		c.Fragment = uint32(v)
	case "ping":
		v, err := parseUint(args, 31)
		if err != nil {
			return err
		}
		c.PingInterval = int(v)
	case "ping-restart":
		v, err := parseUint(args, 31)
		if err != nil {
			return err
		}
		c.PingRestart = int(v)
	case "keepalive":
		if err := need(args, 2); err != nil {
			return err
		}
		a, err := parseUint(args[:1], 31)
		if err != nil {
			return err
		}
		b, err := parseUint(args[1:2], 31)
		if err != nil {
			return err
		}
		c.PingInterval, c.PingRestart = int(a), int(b)
	case "reneg-sec":
		v, err := parseUint(args, 31)
		if err != nil {
			return err
		}
		c.RenegSec = int(v)
		c.RenegDisabled = v == 0
	case "reneg-bytes":
		v, err := parseUint(args, 64)
		if err != nil {
			return err
		}
		c.RenegBytes = v
	case "reneg-pkts":
		v, err := parseUint(args, 64)
		if err != nil {
			return err
		}
		c.RenegPackets = v
	case "hand-window":
		v, err := parseUint(args, 31)
		if err != nil {
			return err
		}
		c.HandWindow = int(v)
	case "tls-timeout":
		v, err := parseUint(args, 31)
		if err != nil {
			return err
		}
		c.TLSTimeout = int(v)
	case "replay-window":
		v, err := parseUint(args, 32)
		if err != nil {
			return err
		}
		c.ReplayWindow = uint32(v)
		if len(args) > 1 {
			t, err := parseUint(args[1:], 31)
			if err != nil {
				return err
			}
			c.ReplayWindowTime = int(t)
		}
	case "route-nopull":
		c.RouteNoPull = true
	case "pull-filter":
		if err := need(args, 2); err != nil {
			return err
		}
		switch args[0] {
		case "accept", "ignore", "reject":
		default:
			return fmt.Errorf("неизвестное действие %q", args[0])
		}
		c.PullFilters = append(c.PullFilters, PullFilter{Action: args[0], Text: args[1]})
	case "route":
		if err := need(args, 1); err != nil {
			return err
		}
		prefix, ok, err := parseRoute(args)
		if err != nil {
			return err
		}
		if !ok {
			p.warn("route %s с именем хоста или ключевым словом пропущен", args[0])
			return nil
		}
		c.Routes = append(c.Routes, prefix)
	case "route-ipv6":
		if err := need(args, 1); err != nil {
			return err
		}
		prefix, err := netip.ParsePrefix(args[0])
		if err != nil {
			return err
		}
		c.Routes = append(c.Routes, prefix)
	case "redirect-gateway":
		c.RedirectGateway = true
		c.RedirectGatewayFlags = append(c.RedirectGatewayFlags, args...)
	case "block-ipv6":
		c.BlockIPv6 = true
	case "explicit-exit-notify":
		c.ExplicitExitNotify = 1
		if len(args) > 0 {
			v, err := parseUint(args, 32)
			if err != nil {
				return err
			}
			c.ExplicitExitNotify = uint32(v)
		}
	case "pkcs12":
		return fmt.Errorf("PKCS#12 не поддерживается, сконвертируйте в PEM (ca/cert/key)")
	case "cryptoapicert":
		return fmt.Errorf("сертификаты из хранилища Windows не поддерживаются, экспортируйте их в PEM")
	case "http-proxy", "socks-proxy":
		return fmt.Errorf("подключение через %s не поддерживается", name)
	case "askpass":
		return fmt.Errorf("ключ с паролем не поддерживается, снимите пароль с ключа")
	default:
		if !ignored[name] {
			p.warn("директива %q не поддерживается и проигнорирована", name)
		}
	}
	return nil
}

func (p *parser) finish() (*Config, error) {
	c := p.cfg
	if len(c.Remotes) == 0 {
		return nil, fmt.Errorf("в конфиге нет ни одного remote")
	}
	if c.CA == "" && len(c.PeerFingerprints) == 0 {
		return nil, fmt.Errorf("нет сертификата CA (<ca> или ca) и peer-fingerprint")
	}
	if (c.Cert == "") != (c.Key == "") {
		return nil, fmt.Errorf("cert и key должны быть заданы вместе")
	}
	if c.Cert == "" && !c.AuthUserPass {
		return nil, fmt.Errorf("нет ни клиентского сертификата, ни auth-user-pass")
	}
	switch p.tlsAuthDirection {
	case "":
	case "0":
		c.KeyDirection = "server"
	case "1":
		c.KeyDirection = "client"
	default:
		return nil, fmt.Errorf("неизвестное направление ключа %q", p.tlsAuthDirection)
	}
	return c, nil
}

func (p *parser) resolve(path string) string {
	if filepath.IsAbs(path) || p.baseDir == "" {
		return path
	}
	return filepath.Join(p.baseDir, path)
}

func (p *parser) readFile(path string) (string, error) {
	b, err := os.ReadFile(p.resolve(path))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (p *parser) setCredentials(content string) error {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	if len(lines) > 0 {
		p.cfg.Username = strings.TrimSpace(lines[0])
	}
	if len(lines) > 1 {
		p.cfg.Password = strings.TrimRight(lines[1], " \t")
	}
	return nil
}

// splitArgs разбивает строку так же, как OpenVPN: пробелы, кавычки и
// экранирование обратной косой чертой.
func splitArgs(line string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inArg := false
	var quote rune
	escaped := false
	for _, r := range line {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && quote != '\'':
			escaped = true
			inArg = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
			inArg = true
		case r == ' ' || r == '\t':
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		case (r == '#' || r == ';') && !inArg:
			// комментарий до конца строки
			return args, nil
		default:
			cur.WriteRune(r)
			inArg = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("незакрытая кавычка")
	}
	if inArg {
		args = append(args, cur.String())
	}
	return args, nil
}

func need(args []string, n int) error {
	if len(args) < n {
		return fmt.Errorf("ожидается аргументов: %d", n)
	}
	return nil
}

func parseUint(args []string, bits int) (uint64, error) {
	if err := need(args, 1); err != nil {
		return 0, err
	}
	return strconv.ParseUint(args[0], 10, bits)
}

func parsePort(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("неверный порт %q", s)
	}
	return uint16(v), nil
}

func normalizeProto(s string) (string, error) {
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, "-client")
	switch s {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
		return s, nil
	default:
		return "", fmt.Errorf("неподдерживаемый протокол %q", s)
	}
}

// parseRoute понимает "route 10.0.0.0 255.0.0.0 [gateway] [metric]" и
// "route 10.0.0.1". Возвращает ok=false для маршрутов с именами хостов.
func parseRoute(args []string) (netip.Prefix, bool, error) {
	addr, err := netip.ParseAddr(args[0])
	if err != nil {
		return netip.Prefix{}, false, nil
	}
	bits := 32
	if len(args) > 1 && args[1] != "default" {
		mask, err := netip.ParseAddr(args[1])
		if err != nil || !mask.Is4() {
			return netip.Prefix{}, false, fmt.Errorf("неверная маска %q", args[1])
		}
		b := mask.As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		ones := 0
		for v&0x80000000 != 0 {
			ones++
			v <<= 1
		}
		if v != 0 {
			return netip.Prefix{}, false, fmt.Errorf("несмежная маска %q", args[1])
		}
		bits = ones
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false, err
	}
	return prefix, true, nil
}

func normalizeFingerprint(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
}
