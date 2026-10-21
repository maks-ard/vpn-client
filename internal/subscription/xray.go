package subscription

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/maks-ard/vpn-client/internal/vless"
)

// Формат Xray JSON: панели (Remnawave и др.) для части клиентов отдают не
// ссылки, а массив готовых конфигов Xray — по одному на сервер, плюс
// конфиги-балансировщики вроде «Авто» с несколькими outbound.

type xrayConfig struct {
	Remarks string `json:"remarks"`
	DNS     struct {
		Hosts map[string]json.RawMessage `json:"hosts"`
	} `json:"dns"`
	Outbounds []xrayOutbound `json:"outbounds"`
}

type xrayOutbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings xrayStream      `json:"streamSettings"`
}

type xrayUser struct {
	ID         string `json:"id"`
	Flow       string `json:"flow"`
	Encryption string `json:"encryption"`
}

type xrayVLESSSettings struct {
	// Классический формат: vnext → users.
	Vnext []struct {
		Address string     `json:"address"`
		Port    int        `json:"port"`
		Users   []xrayUser `json:"users"`
	} `json:"vnext"`
	// Новый плоский формат Xray.
	Address string `json:"address"`
	Port    int    `json:"port"`
	xrayUser
}

type xrayStream struct {
	Network  string `json:"network"`
	Security string `json:"security"`
	TLS      struct {
		ServerName    string   `json:"serverName"`
		Fingerprint   string   `json:"fingerprint"`
		ALPN          []string `json:"alpn"`
		AllowInsecure bool     `json:"allowInsecure"`
	} `json:"tlsSettings"`
	Reality struct {
		ServerName  string `json:"serverName"`
		Fingerprint string `json:"fingerprint"`
		PublicKey   string `json:"publicKey"`
		// В новых версиях Xray публичный ключ называется password.
		Password string `json:"password"`
		ShortID  string `json:"shortId"`
	} `json:"realitySettings"`
	WS struct {
		Path    string            `json:"path"`
		Host    string            `json:"host"`
		Headers map[string]string `json:"headers"`
	} `json:"wsSettings"`
	GRPC struct {
		ServiceName string `json:"serviceName"`
	} `json:"grpcSettings"`
	HTTPUpgrade struct {
		Path string `json:"path"`
		Host string `json:"host"`
	} `json:"httpupgradeSettings"`
	HTTP struct {
		Path string   `json:"path"`
		Host []string `json:"host"`
	} `json:"httpSettings"`
}

func isJSON(text string) bool {
	return strings.HasPrefix(text, "[") || strings.HasPrefix(text, "{")
}

// parseXrayJSON достаёт VLESS-серверы из подписки в формате Xray JSON.
func parseXrayJSON(text string) (links []*vless.Link, skipped []string, err error) {
	var configs []xrayConfig
	if strings.HasPrefix(text, "{") {
		var one xrayConfig
		if err := json.Unmarshal([]byte(text), &one); err != nil {
			return nil, nil, fmt.Errorf("подписка в формате JSON не разобрана: %w", err)
		}
		configs = []xrayConfig{one}
	} else if err := json.Unmarshal([]byte(text), &configs); err != nil {
		return nil, nil, fmt.Errorf("подписка в формате JSON не разобрана: %w", err)
	}

	type candidate struct {
		link *vless.Link
		key  string
	}
	var single, multi []candidate
	seenSkip := map[string]bool{}
	for _, cfg := range configs {
		var found []candidate
		var cfgSkipped []string
		proxies := 0
		for _, ob := range cfg.Outbounds {
			switch ob.Protocol {
			case "freedom", "blackhole", "dns", "loopback", "":
				continue
			}
			proxies++
			if ob.Protocol != "vless" {
				cfgSkipped = append(cfgSkipped, fmt.Sprintf("%s: протокол %s пока не поддерживается", nameOr(cfg.Remarks, ob.Tag), ob.Protocol))
				continue
			}
			raw, err := xrayToVLESSURL(ob, cfg)
			if err != nil {
				cfgSkipped = append(cfgSkipped, fmt.Sprintf("%s: %v", nameOr(cfg.Remarks, ob.Tag), err))
				continue
			}
			link, err := vless.Parse(raw)
			if err != nil {
				cfgSkipped = append(cfgSkipped, fmt.Sprintf("%s: %v", nameOr(cfg.Remarks, ob.Tag), err))
				continue
			}
			found = append(found, candidate{link: link, key: serverKey(link)})
		}
		// Пропуски внутри балансировщика не показываем: те же серверы есть
		// отдельными конфигами и сообщат о себе сами.
		if proxies <= 1 {
			for _, msg := range cfgSkipped {
				if !seenSkip[msg] {
					seenSkip[msg] = true
					skipped = append(skipped, msg)
				}
			}
		}
		switch len(found) {
		case 0:
		case 1:
			found[0].link.Name = nameOr(cfg.Remarks, found[0].link.Name)
			single = append(single, found[0])
		default:
			// Балансировщик («Авто»): его серверы повторяют отдельные конфиги,
			// а выбор самого быстрого делаем сами.
			multi = append(multi, found...)
		}
	}

	// Серверы балансировщика берём, только если отдельных конфигов нет:
	// адреса в нём служебные (rmn-…), поэтому дубли не распознаются,
	// а имена — технические теги outbound'ов.
	candidates := single
	if len(candidates) == 0 {
		candidates = multi
	}
	seen := map[string]bool{}
	for _, c := range candidates {
		if seen[c.key] {
			continue
		}
		seen[c.key] = true
		links = append(links, c.link)
	}
	return links, skipped, nil
}

// xrayToVLESSURL переводит outbound Xray в ссылку vless://, чтобы проверить
// и разобрать её тем же кодом, что и обычные ссылки.
func xrayToVLESSURL(ob xrayOutbound, cfg xrayConfig) (string, error) {
	var s xrayVLESSSettings
	if err := json.Unmarshal(ob.Settings, &s); err != nil {
		return "", fmt.Errorf("неверные settings: %w", err)
	}
	address, port, user := s.Address, s.Port, s.xrayUser
	if len(s.Vnext) > 0 {
		address, port = s.Vnext[0].Address, s.Vnext[0].Port
		if len(s.Vnext[0].Users) > 0 {
			user = s.Vnext[0].Users[0]
		}
	}
	if address == "" || port == 0 || user.ID == "" {
		return "", fmt.Errorf("нет адреса, порта или UUID")
	}
	// Панели часто пишут в address служебное имя, а IP кладут в dns.hosts.
	host := address
	if ip := lookupHost(cfg.DNS.Hosts, address); ip != "" {
		host = ip
	}

	st := ob.StreamSettings
	q := url.Values{}
	q.Set("encryption", "none")
	if user.Encryption != "" {
		q.Set("encryption", user.Encryption)
	}
	if user.Flow != "" {
		q.Set("flow", user.Flow)
	}
	security := st.Security
	if security == "" {
		security = "none"
	}
	q.Set("security", security)
	switch security {
	case "tls":
		setIf(q, "sni", st.TLS.ServerName)
		setIf(q, "fp", st.TLS.Fingerprint)
		if len(st.TLS.ALPN) > 0 {
			q.Set("alpn", strings.Join(st.TLS.ALPN, ","))
		}
		if st.TLS.AllowInsecure {
			q.Set("allowInsecure", "1")
		}
		if st.TLS.ServerName == "" && host != address && strings.Contains(address, ".") {
			q.Set("sni", address)
		}
	case "reality":
		setIf(q, "sni", st.Reality.ServerName)
		setIf(q, "fp", st.Reality.Fingerprint)
		pbk := st.Reality.PublicKey
		if pbk == "" {
			pbk = st.Reality.Password
		}
		setIf(q, "pbk", pbk)
		setIf(q, "sid", st.Reality.ShortID)
	}

	network := st.Network
	if network == "" {
		network = "tcp"
	}
	q.Set("type", network)
	switch network {
	case "ws":
		setIf(q, "path", st.WS.Path)
		h := st.WS.Host
		if h == "" {
			h = st.WS.Headers["Host"]
		}
		setIf(q, "host", h)
	case "grpc":
		setIf(q, "serviceName", st.GRPC.ServiceName)
	case "httpupgrade":
		setIf(q, "path", st.HTTPUpgrade.Path)
		setIf(q, "host", st.HTTPUpgrade.Host)
	case "http", "h2":
		setIf(q, "path", st.HTTP.Path)
		setIf(q, "host", strings.Join(st.HTTP.Host, ","))
	}

	u := url.URL{
		Scheme:   "vless",
		User:     url.User(user.ID),
		Host:     joinHostPort(host, port),
		RawQuery: q.Encode(),
		Fragment: ob.Tag,
	}
	return u.String(), nil
}

func lookupHost(hosts map[string]json.RawMessage, name string) string {
	raw, ok := hosts[name]
	if !ok {
		return ""
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil && len(many) > 0 {
		return many[0]
	}
	return ""
}

func joinHostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

func setIf(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func nameOr(name, fallback string) string {
	if strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	return fallback
}

// serverKey отличает реально разные серверы: одинаковые адрес, UUID и
// параметры транспорта — это один и тот же сервер под разными именами.
func serverKey(l *vless.Link) string {
	return strings.Join([]string{l.Server, strconv.Itoa(int(l.Port)), l.UUID, l.Security, l.SNI,
		l.PublicKey, l.ShortID, l.Transport, l.Path, l.Host, l.ServiceName, l.Flow}, "|")
}
