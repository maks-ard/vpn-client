package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Куда направлять трафик категории.
const (
	// ActionAuto — категория ничего не меняет: трафик идёт как весь остальной.
	ActionAuto   = "auto"
	ActionCorp   = "corp"
	ActionProxy  = "proxy"
	ActionDirect = "direct"
	ActionBlock  = "block"
)

// Типы правил своей категории.
const (
	// RuleDomain — домен вместе с поддоменами.
	RuleDomain = "domain"
	// RuleKeyword — любой домен, в котором встречается эта строка.
	RuleKeyword = "keyword"
	RuleCIDR    = "cidr"
	RuleProcess = "process"
	// RuleSet — ссылка на бинарный rule-set sing-box (.srs).
	RuleSet = "ruleset"
)

const (
	maxCategories        = 100
	maxRulesPerCategory  = 2000
	maxRuleValueLen      = 2048
	maxCategoryNameRunes = 64

	categoryFileFormat  = "vpnclient-category"
	categoryFileVersion = 1
	// MaxCategoryFile — предел размера файла категории при импорте.
	MaxCategoryFile = 256 << 10
)

var (
	categoryIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	hostRe       = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$`)
)

// Category — группа правил с одним направлением. Готовая категория
// (Preset) ссылается на каталог в пакете singbox и своих правил не хранит.
type Category struct {
	ID     string `yaml:"id" json:"id"`
	Preset bool   `yaml:"preset,omitempty" json:"preset,omitempty"`
	Name   string `yaml:"name,omitempty" json:"name,omitempty"`
	Action string `yaml:"action" json:"action"`
	Rules  []Rule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

type Rule struct {
	Type  string `yaml:"type" json:"type"`
	Value string `yaml:"value" json:"value"`
}

// NormalizeCategories проверяет список и приводит значения к виду, который
// понимает генератор конфига. Порядок категорий сохраняется: он задаёт приоритет.
func NormalizeCategories(in []Category) ([]Category, error) {
	if len(in) > maxCategories {
		return nil, fmt.Errorf("категорий слишком много (не больше %d)", maxCategories)
	}
	out := make([]Category, 0, len(in))
	seen := map[string]bool{}
	for _, c := range in {
		c, err := normalizeCategory(c)
		if err != nil {
			return nil, err
		}
		if seen[c.ID] {
			return nil, fmt.Errorf("категория %q указана дважды", c.ID)
		}
		seen[c.ID] = true
		out = append(out, c)
	}
	return out, nil
}

func normalizeCategory(c Category) (Category, error) {
	c.ID = strings.TrimSpace(c.ID)
	if !categoryIDRe.MatchString(c.ID) {
		return c, fmt.Errorf("категория %q: идентификатор должен состоять из латиницы, цифр, - и _", c.ID)
	}
	switch c.Action {
	case ActionAuto, ActionCorp, ActionProxy, ActionDirect, ActionBlock:
	default:
		return c, fmt.Errorf("категория %q: неизвестное направление %q", c.ID, c.Action)
	}
	c.Name = strings.TrimSpace(c.Name)
	if c.Preset {
		if len(c.Rules) > 0 {
			return c, fmt.Errorf("категория %q: у готовой категории не бывает своих правил", c.ID)
		}
		c.Rules = nil
		return c, nil
	}
	if c.Name == "" {
		return c, fmt.Errorf("категория %q: укажите название", c.ID)
	}
	if utf8.RuneCountInString(c.Name) > maxCategoryNameRunes {
		return c, fmt.Errorf("категория %q: название длиннее %d символов", c.ID, maxCategoryNameRunes)
	}
	rules, err := NormalizeRules(c.Rules)
	if err != nil {
		return c, fmt.Errorf("категория %q: %w", c.Name, err)
	}
	c.Rules = rules
	return c, nil
}

// NormalizeRules проверяет правила и убирает повторы.
func NormalizeRules(in []Rule) ([]Rule, error) {
	if len(in) > maxRulesPerCategory {
		return nil, fmt.Errorf("правил слишком много (не больше %d)", maxRulesPerCategory)
	}
	out := make([]Rule, 0, len(in))
	seen := map[Rule]bool{}
	for _, r := range in {
		r, err := normalizeRule(r)
		if err != nil {
			return nil, err
		}
		if seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out, nil
}

func normalizeRule(r Rule) (Rule, error) {
	v := strings.TrimSpace(r.Value)
	if v == "" {
		return r, errors.New("пустое правило")
	}
	if len(v) > maxRuleValueLen {
		return r, errors.New("правило слишком длинное")
	}
	switch r.Type {
	case RuleDomain:
		v = strings.ToLower(strings.Trim(v, "."))
		v = strings.TrimPrefix(v, "*.")
		if err := checkHost(v); err != nil {
			return r, err
		}
	case RuleKeyword:
		v = strings.ToLower(v)
		if utf8.RuneCountInString(v) < 3 {
			return r, fmt.Errorf("часть адреса %q слишком короткая: нужно хотя бы 3 символа, иначе правило заденет лишнее", v)
		}
		if strings.ContainsAny(v, " /\\:@") {
			return r, fmt.Errorf("часть адреса %q не должна содержать пробелы и знаки / \\ : @", v)
		}
		if !isASCII(v) {
			return r, fmt.Errorf("%q: кириллицу и другие не латинские символы в адресах нужно писать в punycode", v)
		}
	case RuleCIDR:
		if p, err := netip.ParsePrefix(v); err == nil {
			v = p.Masked().String()
		} else if a, err := netip.ParseAddr(v); err == nil {
			v = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()).String()
		} else {
			return r, fmt.Errorf("%q не похоже на IP-адрес или подсеть", v)
		}
	case RuleProcess:
		if strings.ContainsAny(v, `/\`) {
			return r, fmt.Errorf("программа %q: укажите имя файла без пути, например telegram.exe", v)
		}
	case RuleSet:
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || !strings.HasSuffix(strings.ToLower(u.Path), ".srs") {
			return r, fmt.Errorf("%q: нужна ссылка https:// на файл .srs", v)
		}
	default:
		return r, fmt.Errorf("неизвестный тип правила %q", r.Type)
	}
	return Rule{Type: r.Type, Value: v}, nil
}

func checkHost(d string) error {
	if !isASCII(d) {
		return fmt.Errorf("%q: кириллицу и другие не латинские символы в адресах нужно писать в punycode (например, xn--p1ai вместо рф)", d)
	}
	if len(d) > 253 || !hostRe.MatchString(d) {
		return fmt.Errorf("%q не похоже на домен", d)
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// categoryFile — формат обмена. Направление в файл не входит: его выбирает
// тот, кто импортирует, чтобы чужой файл не мог сам отправить трафик куда-то.
type categoryFile struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	Name    string `json:"name"`
	Rules   []Rule `json:"rules"`
}

// ExportCategory сериализует свою категорию для передачи другому человеку.
func ExportCategory(c Category) ([]byte, error) {
	if c.Preset {
		return nil, errors.New("готовые категории не экспортируются: они есть в каталоге у всех")
	}
	c, err := normalizeCategory(Category{ID: "export", Name: c.Name, Action: ActionAuto, Rules: c.Rules})
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(categoryFile{Format: categoryFileFormat, Version: categoryFileVersion, Name: c.Name, Rules: c.Rules}, "", "  ")
}

// ParseCategoryFile читает файл категории. Возвращает категорию без
// идентификатора и с направлением «auto»: их назначает вызывающий.
func ParseCategoryFile(data []byte) (Category, error) {
	if len(data) > MaxCategoryFile {
		return Category{}, fmt.Errorf("файл больше %d КБ", MaxCategoryFile>>10)
	}
	var f categoryFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return Category{}, fmt.Errorf("это не файл категории: %w", err)
	}
	if f.Format != categoryFileFormat {
		return Category{}, errors.New("это не файл категории vpn-client")
	}
	if f.Version > categoryFileVersion {
		return Category{}, errors.New("файл создан более новой версией приложения, обновите приложение")
	}
	c, err := normalizeCategory(Category{ID: "import", Name: f.Name, Action: ActionAuto, Rules: f.Rules})
	if err != nil {
		return Category{}, err
	}
	return Category{Name: c.Name, Action: ActionAuto, Rules: c.Rules}, nil
}
