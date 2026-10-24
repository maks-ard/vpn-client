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
// ссылки, а массив готовых конфигов Xray — по одному на точку входа, часто с
// несколькими транспортами и балансировщиком внутри, плюс конфиги вроде
// «Авто», собранные из серверов остальных.

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

// parseXrayJSON достаёт VLESS-серверы из подписки в формате Xray JSON:
// конфиг — один пункт списка, его outbound'ы — варианты подключения.
func parseXrayJSON(text string) (servers []Server, skipped []string, err error) {
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

	entries := make([]xrayEntry, 0, len(configs))
	for _, cfg := range configs {
		e := xrayEntry{keys: map[string]bool{}}
		for _, ob := range cfg.Outbounds {
			switch ob.Protocol {
			case "freedom", "blackhole", "dns", "loopback", "":
				continue
			}
			if ob.Protocol != "vless" {
				e.skipped = append(e.skipped, fmt.Sprintf("%s: протокол %s пока не поддерживается", nameOr(cfg.Remarks, ob.Tag), ob.Protocol))
				continue
			}
			raw, err := xrayToVLESSURL(ob, cfg)
			if err != nil {
				e.skipped = append(e.skipped, fmt.Sprintf("%s: %v", nameOr(cfg.Remarks, ob.Tag), err))
				continue
			}
			link, err := vless.Parse(raw)
			if err != nil {
				e.skipped = append(e.skipped, fmt.Sprintf("%s: %v", nameOr(cfg.Remarks, ob.Tag), err))
				continue
			}
			key := serverKey(link)
			if e.keys[key] {
				continue
			}
			e.keys[key] = true
			e.server.Links = append(e.server.Links, link)
		}
		if len(e.server.Links) > 0 {
			e.server.Name = nameOr(cfg.Remarks, e.server.Links[0].Name)
		}
		entries = append(entries, e)
	}

	seenSkip := map[string]bool{}
	for i, e := range entries {
		// Неподходящие варианты (например, XHTTP) при рабочих соседях не
		// показываем: пункт списка всё равно подключится.
		if len(e.server.Links) == 0 {
			for _, msg := range e.skipped {
				if !seenSkip[msg] {
					seenSkip[msg] = true
					skipped = append(skipped, msg)
				}
			}
			continue
		}
		if covered(entries, i) {
			continue
		}
		servers = append(servers, e.server)
	}
	return servers, skipped, nil
}

type xrayEntry struct {
	server  Server
	keys    map[string]bool
	skipped []string
}

// covered сообщает, что конфиг целиком повторяет другие: так выглядят
// балансировщики вроде «⚡ Авто», собранные из серверов отдельных конфигов.
// Самый быстрый сервер мы выбираем сами, а такой пункт только дублирует список.
func covered(entries []xrayEntry, i int) bool {
	e := entries[i]
	for key := range e.keys {
		found := false
		for j, other := range entries {
			if j == i || !other.keys[key] {
				continue
			}
			smaller := len(other.keys) < len(e.keys)
			sameEarlier := j < i && len(other.keys) == len(e.keys) && sameKeys(other.keys, e.keys)
			if smaller || sameEarlier {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func sameKeys(a, b map[string]bool) bool {
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return len(a) == len(b)
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
