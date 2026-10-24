package profile

import (
	"strings"
	"testing"
)

func TestNormalizeCategories(t *testing.T) {
	good := []Category{
		{ID: "ads", Preset: true, Action: ActionBlock},
		{ID: "work", Name: " Работа ", Action: ActionCorp, Rules: []Rule{
			{RuleDomain, " *.Corp.Example.COM. "},
			{RuleDomain, "corp.example.com"},
			{RuleKeyword, "Slack"},
			{RuleCIDR, "10.1.2.3/16"},
			{RuleCIDR, "192.0.2.7"},
			{RuleProcess, "zoom.exe"},
			{RuleSet, "https://example.com/list.srs"},
		}},
	}
	got, err := NormalizeCategories(good)
	if err != nil {
		t.Fatal(err)
	}
	work := got[1]
	if work.Name != "Работа" || len(work.Rules) != 6 {
		t.Fatalf("name=%q rules=%v", work.Name, work.Rules)
	}
	want := []Rule{{RuleDomain, "corp.example.com"}, {RuleKeyword, "slack"}, {RuleCIDR, "10.1.0.0/16"}, {RuleCIDR, "192.0.2.7/32"}, {RuleProcess, "zoom.exe"}, {RuleSet, "https://example.com/list.srs"}}
	for i, r := range want {
		if work.Rules[i] != r {
			t.Errorf("правило %d = %v, ожидалось %v", i, work.Rules[i], r)
		}
	}
}

func TestNormalizeCategoriesErrors(t *testing.T) {
	custom := func(r Rule) []Category {
		return []Category{{ID: "a", Name: "n", Action: ActionProxy, Rules: []Rule{r}}}
	}
	cases := []struct {
		name string
		in   []Category
		want string
	}{
		{"плохой id", []Category{{ID: "Bad ID", Preset: true, Action: ActionProxy}}, "идентификатор"},
		{"плохое направление", []Category{{ID: "a", Preset: true, Action: "tunnel"}}, "направление"},
		{"повтор", []Category{{ID: "a", Preset: true, Action: ActionProxy}, {ID: "a", Preset: true, Action: ActionDirect}}, "дважды"},
		{"правила у готовой", []Category{{ID: "a", Preset: true, Action: ActionProxy, Rules: []Rule{{RuleDomain, "x.com"}}}}, "готовой"},
		{"без названия", []Category{{ID: "a", Action: ActionProxy}}, "название"},
		{"кириллица в домене", custom(Rule{RuleDomain, "пример.рф"}), "punycode"},
		{"домен с пробелом", custom(Rule{RuleDomain, "a b.com"}), "не похоже на домен"},
		{"короткое слово", custom(Rule{RuleKeyword, "ab"}), "короткая"},
		{"плохая подсеть", custom(Rule{RuleCIDR, "10.0.0.0/99"}), "подсеть"},
		{"программа с путём", custom(Rule{RuleProcess, `C:\x\a.exe`}), "без пути"},
		{"rule-set по http", custom(Rule{RuleSet, "http://example.com/a.srs"}), ".srs"},
		{"rule-set не srs", custom(Rule{RuleSet, "https://example.com/a.json"}), ".srs"},
		{"неизвестный тип", custom(Rule{"regex", ".*"}), "тип правила"},
		{"пустое правило", custom(Rule{RuleDomain, "  "}), "пустое"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NormalizeCategories(c.in)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("ошибка = %v, ожидалась с %q", err, c.want)
			}
		})
	}
}

func TestCategoryExportImport(t *testing.T) {
	data, err := ExportCategory(Category{ID: "work", Name: "Работа", Action: ActionCorp, Rules: []Rule{{RuleDomain, "figma.com"}, {RuleProcess, "zoom.exe"}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "corp") || strings.Contains(string(data), `"id"`) {
		t.Errorf("в файл попали направление или идентификатор:\n%s", data)
	}
	c, err := ParseCategoryFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "Работа" || c.Action != ActionAuto || c.ID != "" || c.Preset || len(c.Rules) != 2 {
		t.Fatalf("импортировано %+v", c)
	}
	if _, err := ExportCategory(Category{ID: "ads", Preset: true, Action: ActionBlock}); err == nil {
		t.Error("готовую категорию экспортировать нельзя")
	}
}

func TestParseCategoryFileErrors(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"не json", "привет", "не файл категории"},
		{"чужой формат", `{"format":"other","version":1,"name":"x","rules":[]}`, "не файл категории"},
		{"новая версия", `{"format":"vpnclient-category","version":9,"name":"x","rules":[]}`, "новой версией"},
		{"лишнее поле", `{"format":"vpnclient-category","version":1,"name":"x","rules":[],"action":"corp"}`, "не файл категории"},
		{"плохое правило", `{"format":"vpnclient-category","version":1,"name":"x","rules":[{"type":"domain","value":"a b"}]}`, "не похоже на домен"},
		{"без названия", `{"format":"vpnclient-category","version":1,"name":"","rules":[]}`, "название"},
		{"слишком большой", strings.Repeat(" ", MaxCategoryFile+1), "больше"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseCategoryFile([]byte(c.in))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("ошибка = %v, ожидалась с %q", err, c.want)
			}
		})
	}
}

func TestProfileCategoriesYAML(t *testing.T) {
	p, err := Parse([]byte(`vless: "vless://id@example.com:443"
routing:
  categories:
    - id: ads
      preset: true
      action: block
    - id: work
      name: Работа
      action: direct
      rules:
        - {type: domain, value: Figma.com}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	cats := p.Routing.Categories
	if len(cats) != 2 || cats[1].Rules[0].Value != "figma.com" {
		t.Fatalf("categories = %+v", cats)
	}
	if _, err := Parse([]byte("vless: \"vless://id@example.com:443\"\nrouting:\n  categories:\n    - {id: a, action: nope, preset: true}\n"), ""); err == nil || !strings.Contains(err.Error(), "routing.categories") {
		t.Errorf("ошибка категории должна указывать на routing.categories: %v", err)
	}
}
