package singbox

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Verdict — куда пойдёт трафик к адресу при текущих правилах.
type Verdict struct {
	// Action — corp (OpenVPN), proxy (VLESS), direct или block.
	Action string `json:"action"`
	// Rule — подпись сработавшего правила; пусто, если сработало «всё остальное».
	Rule string `json:"rule,omitempty"`
	// Target — адрес в том виде, в каком он проверялся.
	Target string `json:"target"`
	// Notes — то, что проверить нельзя и что может изменить результат.
	Notes []string `json:"notes,omitempty"`
}

// SetMatcher отвечает, входит ли адрес в rule-set. Нужен для готовых
// категорий и списков России: их состав известен только самим файлам .srs.
type SetMatcher func(tag, url, target string) (bool, error)

type explainTarget struct {
	text string
	ip   netip.Addr
	isIP bool
}

// ParseTarget понимает домен, IP-адрес и ссылку целиком (https://host:port/path).
func ParseTarget(raw string) (string, error) {
	t, err := parseTarget(raw)
	return t.text, err
}

func parseTarget(raw string) (explainTarget, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return explainTarget{}, errors.New("введите домен или IP-адрес")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return explainTarget{}, fmt.Errorf("не удалось разобрать ссылку %q", raw)
		}
		s = u.Hostname()
	} else {
		if i := strings.IndexAny(s, "/?#"); i >= 0 {
			s = s[:i]
		}
		if i := strings.LastIndex(s, "@"); i >= 0 {
			s = s[i+1:]
		}
		if h, _, ok := strings.Cut(strings.TrimPrefix(s, "["), "]"); ok && strings.HasPrefix(s, "[") {
			s = h
		} else if strings.Count(s, ":") == 1 {
			s, _, _ = strings.Cut(s, ":")
		}
	}
	s = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(s, "*."), "."))
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return explainTarget{text: a.String(), ip: a, isIP: true}, nil
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x80 {
			return explainTarget{}, fmt.Errorf("%q: кириллицу и другие не латинские символы нужно писать в punycode", raw)
		}
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return explainTarget{}, fmt.Errorf("%q не похоже на домен или IP-адрес", raw)
		}
	}
	if s == "" || strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
		return explainTarget{}, fmt.Errorf("%q не похоже на домен или IP-адрес", raw)
	}
	return explainTarget{text: s}, nil
}

type explainState struct {
	serverRoutes, processRules, ipSetsSkipped, noMatcher bool
	errs                                                 []string
}

// Explain прогоняет адрес через те же правила, из которых собирается конфиг,
// и говорит, куда он пойдёт. Правила по программам и маршруты от сервера
// OpenVPN проверить нельзя (они зависят от процесса и подключения): об этом
// сообщается в Notes.
func Explain(in *Input, target string, match SetMatcher) (Verdict, error) {
	tg, err := parseTarget(target)
	if err != nil {
		return Verdict{}, err
	}
	hasProxy := len(in.Servers) > 0
	hasCorp := in.OpenVPN != nil
	cats := resolveCategories(in)

	sets := map[string]string{}
	for _, d := range ruleSetDefsRaw(in, cats) {
		sets[d.tag] = d.url
	}

	v := Verdict{Target: tg.text}
	var st explainState
	final := TagDirect
	if hasProxy {
		final = TagProxy
	}
	outcome := func(rule M) string {
		if rule["action"] == "reject" {
			return "block"
		}
		return actionOf(rule["outbound"])
	}
	v.Action = actionOf(final)
	for _, r := range routeRuleList(in, cats, hasProxy, hasCorp) {
		if ruleMatches(r.rule, tg, sets, match, &st) {
			v.Action, v.Rule = outcome(r.rule), r.label
			break
		}
	}

	if st.serverRoutes {
		v.Notes = append(v.Notes, "Маршруты и домены, которые присылает сервер OpenVPN, проверить нельзя: они известны только после подключения.")
	}
	if st.processRules {
		v.Notes = append(v.Notes, "Правила для программ не проверяются: они зависят от того, какое приложение отправляет запрос.")
	}
	if st.ipSetsSkipped {
		v.Notes = append(v.Notes, "Для домена не проверялись наборы IP-адресов: адрес станет известен только после разрешения имени.")
	}
	if st.noMatcher {
		v.Notes = append(v.Notes, "Готовые наборы сайтов не проверялись.")
	}
	v.Notes = append(v.Notes, st.errs...)
	if len(in.Servers) == 0 && in.Profile.Subscription != nil {
		v.Notes = append(v.Notes, "Список серверов подписки ещё не загружался, поэтому правила для VLESS не учтены.")
	}
	return v, nil
}

func actionOf(outbound any) string {
	switch outbound {
	case TagCorp:
		return "corp"
	case TagProxy:
		return "proxy"
	default:
		return "direct"
	}
}

func toStrings(v any) []string {
	switch list := v.(type) {
	case []string:
		return list
	case []any:
		out := make([]string, 0, len(list))
		for _, item := range list {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// ruleMatches: поля одного правила sing-box объединяет по «и». В наших
// правилах поле одно, но проверка остаётся честной и для нескольких.
func ruleMatches(rule M, tg explainTarget, sets map[string]string, match SetMatcher, st *explainState) bool {
	matched := false
	for key, value := range rule {
		var ok bool
		switch key {
		case "outbound", "action":
			continue
		case "domain_suffix":
			ok = !tg.isIP && anyOf(toStrings(value), func(s string) bool { return tg.text == s || strings.HasSuffix(tg.text, "."+s) })
		case "domain_keyword":
			ok = !tg.isIP && anyOf(toStrings(value), func(s string) bool { return strings.Contains(tg.text, s) })
		case "ip_cidr":
			ok = tg.isIP && anyOf(toStrings(value), func(s string) bool {
				p, err := netip.ParsePrefix(s)
				return err == nil && p.Contains(tg.ip)
			})
		case "ip_is_private":
			ok = tg.isIP && (tg.ip.IsPrivate() || tg.ip.IsLoopback() || tg.ip.IsLinkLocalUnicast())
		case "process_name":
			st.processRules = true
			return false
		case "preferred_by":
			st.serverRoutes = true
			return false
		case "rule_set":
			ok = anyOf(toStrings(value), func(tag string) bool {
				if !tg.isIP && strings.HasPrefix(tag, "geoip-") {
					st.ipSetsSkipped = true
					return false
				}
				if match == nil {
					st.noMatcher = true
					return false
				}
				hit, err := match(tag, sets[tag], tg.text)
				if err != nil {
					st.errs = append(st.errs, fmt.Sprintf("Не удалось проверить набор %s: %v", tag, err))
					return false
				}
				return hit
			})
		default:
			return false
		}
		if !ok {
			return false
		}
		matched = true
	}
	return matched
}

func anyOf(list []string, f func(string) bool) bool {
	for _, s := range list {
		if f(s) {
			return true
		}
	}
	return false
}
