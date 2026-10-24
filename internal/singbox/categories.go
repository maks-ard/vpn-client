package singbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/maks-ard/vpn-client/internal/profile"
)

// Preset — готовая категория сайтов. Состав берётся из наборов sing-geosite.
type Preset struct {
	ID    string
	Title string
	// Examples — что в неё входит, для подписи в окне.
	Examples string
	// Sets — имена наборов sing-geosite без префикса geosite-.
	Sets []string
}

var presets = []Preset{
	{ID: "gov-bank-ru", Title: "Госуслуги и банки РФ", Examples: "Не любят зарубежные IP", Sets: []string{"category-gov-ru", "category-bank-ru"}},
	{ID: "ads", Title: "Реклама и трекеры", Examples: "Рекламные и счётные домены", Sets: []string{"category-ads-all"}},
	{ID: "video", Title: "Видео и музыка", Examples: "YouTube, Netflix, Spotify, Twitch", Sets: []string{"youtube", "netflix", "spotify", "twitch"}},
	{ID: "social", Title: "Соцсети и мессенджеры", Examples: "Telegram, Instagram, Facebook, X, WhatsApp, TikTok, Discord", Sets: []string{"telegram", "instagram", "facebook", "twitter", "whatsapp", "tiktok", "discord"}},
	{ID: "ai", Title: "ИИ-сервисы", Examples: "OpenAI, Anthropic и другие чат-боты", Sets: []string{"openai", "anthropic", "category-ai-chat-!cn"}},
	{ID: "dev", Title: "Разработка", Examples: "GitHub, npm, Docker Hub и другие", Sets: []string{"github", "category-dev"}},
	{ID: "games", Title: "Игры", Examples: "Steam, Epic Games и другие", Sets: []string{"steam", "category-games"}},
}

// Presets возвращает каталог готовых категорий в порядке показа.
func Presets() []Preset {
	return append([]Preset(nil), presets...)
}

func presetByID(id string) (Preset, bool) {
	for _, p := range presets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

const geositeURL = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-%s.srs"

type ruleSetDef struct{ tag, url string }

// resolvedCategory — категория, разобранная под конкретный набор подключений.
type resolvedCategory struct {
	action                                     string
	suffixes, keywords, cidrs, processes, sets []string
	// domainSets — наборы, годные для DNS-правил: только домены. Наборы по
	// ссылке пользователя могут содержать IP-правила, в DNS их не кладём.
	domainSets []string
}

type resolved struct {
	cats     []resolvedCategory
	sets     []ruleSetDef
	warnings []string
}

// resolveCategories превращает категории профиля в готовые к выводу правила.
// Категории, которым некуда направлять трафик (нет OpenVPN или VLESS),
// пропускаются с замечанием: подключение из-за них не должно ломаться.
func resolveCategories(in *Input) resolved {
	var out resolved
	hasProxy := len(in.Servers) > 0
	hasCorp := in.OpenVPN != nil
	seenSets := map[string]bool{}
	addSet := func(tag, url string) {
		if !seenSets[tag] {
			seenSets[tag] = true
			out.sets = append(out.sets, ruleSetDef{tag: tag, url: url})
		}
	}

	for _, c := range in.Profile.Routing.Categories {
		if c.Action == profile.ActionAuto {
			continue
		}
		title := c.Name
		rc := resolvedCategory{action: c.Action}

		if c.Preset {
			p, ok := presetByID(c.ID)
			if !ok {
				out.warnings = append(out.warnings, fmt.Sprintf("категория %q неизвестна этой версии, пропущена", c.ID))
				continue
			}
			title = p.Title
			for _, name := range p.Sets {
				tag := "geosite-" + name
				addSet(tag, fmt.Sprintf(geositeURL, name))
				rc.sets = append(rc.sets, tag)
				rc.domainSets = append(rc.domainSets, tag)
			}
		} else {
			for _, r := range c.Rules {
				switch r.Type {
				case profile.RuleDomain:
					rc.suffixes = append(rc.suffixes, r.Value)
				case profile.RuleKeyword:
					rc.keywords = append(rc.keywords, r.Value)
				case profile.RuleCIDR:
					rc.cidrs = append(rc.cidrs, r.Value)
				case profile.RuleProcess:
					rc.processes = append(rc.processes, r.Value)
				case profile.RuleSet:
					sum := sha256.Sum256([]byte(r.Value))
					tag := "user-" + hex.EncodeToString(sum[:5])
					addSet(tag, r.Value)
					rc.sets = append(rc.sets, tag)
				}
			}
		}

		switch {
		case c.Action == profile.ActionCorp && !hasCorp:
			out.warnings = append(out.warnings, fmt.Sprintf("категория %q направлена в OpenVPN, но профиль OpenVPN не загружен, пропущена", title))
			continue
		case c.Action == profile.ActionProxy && !hasProxy:
			out.warnings = append(out.warnings, fmt.Sprintf("категория %q направлена через VLESS, но сервера нет, пропущена", title))
			continue
		}
		if len(rc.suffixes)+len(rc.keywords)+len(rc.cidrs)+len(rc.processes)+len(rc.sets) == 0 {
			continue
		}
		out.cats = append(out.cats, rc)
	}
	return out
}

func outboundFor(action string) string {
	switch action {
	case profile.ActionCorp:
		return TagCorp
	case profile.ActionProxy:
		return TagProxy
	default:
		return TagDirect
	}
}

func dnsServerFor(action string) string {
	switch action {
	case profile.ActionCorp:
		return TagDNSCorp
	case profile.ActionProxy:
		return TagDNSRemote
	default:
		return TagDNSDirect
	}
}

// routeRules возвращает правила маршрутов. corp выбирает, какие категории
// выводить: направленные в OpenVPN обязаны стоять выше частных сетей, иначе
// корпоративные подсети вида 10.x уйдут напрямую. Поля одного правила
// sing-box объединяет по «и», поэтому каждый тип пишется отдельным правилом.
func (r resolved) routeRules(corp bool) []any {
	var rules []any
	for _, c := range r.cats {
		if (c.action == profile.ActionCorp) != corp {
			continue
		}
		add := func(key string, values []string) {
			if len(values) == 0 {
				return
			}
			rule := M{key: values}
			if c.action == profile.ActionBlock {
				rule["action"] = "reject"
			} else {
				rule["outbound"] = outboundFor(c.action)
			}
			rules = append(rules, rule)
		}
		add("domain_suffix", c.suffixes)
		add("domain_keyword", c.keywords)
		add("ip_cidr", c.cidrs)
		add("process_name", c.processes)
		add("rule_set", c.sets)
	}
	return rules
}

// dnsRules — то же для DNS: только то, что опознаётся по имени домена.
func (r resolved) dnsRules(corp bool) []any {
	var rules []any
	for _, c := range r.cats {
		if (c.action == profile.ActionCorp) != corp {
			continue
		}
		add := func(key string, values []string) {
			if len(values) == 0 {
				return
			}
			rule := M{key: values}
			if c.action == profile.ActionBlock {
				rule["action"] = "reject"
			} else {
				rule["server"] = dnsServerFor(c.action)
			}
			rules = append(rules, rule)
		}
		add("domain_suffix", c.suffixes)
		add("domain_keyword", c.keywords)
		add("rule_set", c.domainSets)
	}
	return rules
}
