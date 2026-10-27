// Package openvpn запускает OpenVPN, установленный пользователем (openvpn.exe
// из OpenVPN Community), и разбирает его журнал: когда туннель поднялся, через
// какой адаптер и что прислал сервер. Корпоративный трафик тогда идёт через
// адаптер настоящего OpenVPN, а не через endpoint внутри sing-box.
package openvpn

import (
	"bufio"
	"fmt"
	"strings"
)

// DefaultRouteMetric — метрика маршрута по умолчанию через адаптер OpenVPN.
// sing-box открывает корпоративные соединения сокетом, привязанным к адаптеру,
// и без маршрута через адаптер они не открываются. Метрика большая, чтобы
// маршрут не перебивал ни TUN, ни основной шлюз.
const DefaultRouteMetric = 9999

// header идёт до конфига пользователя: из одинаковых pull-filter срабатывает
// первый, и правила из .ovpn не могут их отменить.
//
// Сервер не должен забирать весь трафик и менять DNS Windows: при
// strict_route sing-box закрывает DNS мимо TUN, и запросы Windows к серверам
// компании (в том числе по правилам NRPT) не прошли бы. Имена компании
// разрешает sing-box: DNS и домены от сервера служба берёт из журнала.
var header = []string{
	`pull-filter ignore "redirect-gateway"`,
	`pull-filter ignore "block-outside-dns"`,
	`pull-filter ignore "dhcp-option"`,
	`pull-filter ignore "dns "`,
	fmt.Sprintf("route 0.0.0.0 0.0.0.0 vpn_gateway %d", DefaultRouteMetric),
}

// dropped — директивы, которые нельзя передавать openvpn.exe. Служба работает
// от имени SYSTEM, а .ovpn загружает обычный пользователь: скрипты, плагины,
// движки OpenSSL и файлы, которые пишет OpenVPN, дали бы ему права системы.
// Остальные директивы — то, что служба делает сама, или то, что ломает
// разбор журнала.
var dropped = byReason(map[string][]string{
	"скрипты": {"script-security", "up", "down", "route-up", "route-pre-down", "ipchange",
		"tls-verify", "learn-address", "client-connect", "client-disconnect", "auth-user-pass-verify"},
	"плагины":           {"plugin"},
	"модули OpenSSL":    {"engine", "providers", "provider-path", "pkcs11-providers"},
	"журнал":            {"log", "log-append", "syslog"},
	"запись файлов":     {"status", "writepid", "tls-export-cert", "replay-persist", "tmp-dir", "cd", "chroot"},
	"вложенные конфиги": {"config"},
	"служба":            {"daemon", "service", "user", "group"},
	"ввод пароля":       {"askpass"},
	"маршруты":          {"redirect-gateway", "redirect-private"},
	"DNS":               {"block-outside-dns", "dhcp-option", "dns", "register-dns"},
})

func byReason(m map[string][]string) map[string]string {
	out := map[string]string{}
	for why, names := range m {
		for _, name := range names {
			out[name] = why
		}
	}
	return out
}

// fileOptions читают файл, путь к которому указан в директиве. От имени
// SYSTEM так можно прочитать чужой файл, поэтому разрешено только
// содержимое внутри .ovpn ([inline] или блок <ca>…</ca>).
var fileOptions = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true,
	"tls-crypt-v2": true, "secret": true, "pkcs12": true, "crl-verify": true,
	"extra-certs": true, "dh": true, "auth-user-pass": true, "http-proxy-user-pass": true,
}

// Config готовит конфиг для `openvpn --config stdin`: опасные и мешающие
// директивы убираются, логин и пароль (если заданы) встраиваются в конфиг,
// чтобы не лежать на диске. Возвращает конфиг и замечания о том, что убрано.
func Config(ovpn []byte, username, password string) ([]byte, []string, error) {
	if strings.ContainsAny(username, "\r\n") || strings.ContainsAny(password, "\r\n") {
		return nil, nil, fmt.Errorf("логин и пароль OpenVPN не должны содержать перевода строки")
	}
	var out strings.Builder
	for _, line := range header {
		out.WriteString(line + "\n")
	}
	var warnings []string
	warn := func(name, why string) {
		w := fmt.Sprintf("директива %s пропущена (%s)", name, why)
		for _, seen := range warnings {
			if seen == w {
				return
			}
		}
		warnings = append(warnings, w)
	}

	block := "" // имя inline-блока, внутри которого идёт строка
	sc := bufio.NewScanner(strings.NewReader(string(ovpn)))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if block != "" {
			skip := block == "auth-user-pass" && username != ""
			if strings.EqualFold(trimmed, "</"+block+">") {
				block = ""
			}
			if !skip {
				out.WriteString(line + "\n")
			}
			continue
		}
		if strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">") {
			tag := strings.ToLower(strings.Trim(trimmed, "<>/"))
			// В блоке <connection> обычные директивы: проверяем их как остальные.
			if tag == "connection" || strings.HasPrefix(trimmed, "</") {
				out.WriteString(line + "\n")
				continue
			}
			block = tag
			// Свои логин и пароль заменяют встроенные в .ovpn.
			if block != "auth-user-pass" || username == "" {
				out.WriteString(line + "\n")
			}
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], ";") {
			out.WriteString(line + "\n")
			continue
		}
		name := strings.ToLower(strings.TrimPrefix(fields[0], "--"))
		if why, ok := dropped[name]; ok || strings.HasPrefix(name, "management") {
			if !ok {
				why = "служба"
			}
			warn(name, why)
			continue
		}
		if fileOptions[name] && len(fields) > 1 && fields[1] != "[inline]" {
			warn(name, "путь к файлу; загрузите .ovpn заново, чтобы встроить содержимое")
			continue
		}
		if (name == "http-proxy" || name == "socks-proxy") && len(fields) > 3 && !proxyAuthKeyword(fields[3]) {
			warn(name, "файл с паролем прокси")
			continue
		}
		out.WriteString(line + "\n")
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("openvpn: %w", err)
	}
	if block != "" {
		return nil, nil, fmt.Errorf("openvpn: блок <%s> не закрыт", block)
	}
	// Служба узнаёт о подключении из журнала: сообщения о маршрутах и DNS
	// от сервера пишутся начиная с verb 3.
	out.WriteString("verb 3\n")
	if username != "" {
		fmt.Fprintf(&out, "<auth-user-pass>\n%s\n%s\n</auth-user-pass>\n", username, password)
	}
	return []byte(out.String()), warnings, nil
}

func proxyAuthKeyword(s string) bool {
	switch strings.ToLower(s) {
	case "auto", "auto-nct", "stdin", "[inline]":
		return true
	}
	return false
}
