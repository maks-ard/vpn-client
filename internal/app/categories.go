package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/maks-ard/vpn-client/internal/profile"
	"github.com/maks-ard/vpn-client/internal/singbox"
)

// PresetInfo — готовая категория для списка в окне.
type PresetInfo struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Examples string `json:"examples"`
}

// Presets возвращает каталог готовых категорий.
func Presets() []PresetInfo {
	var out []PresetInfo
	for _, p := range singbox.Presets() {
		out = append(out, PresetInfo{ID: p.ID, Title: p.Title, Examples: p.Examples})
	}
	return out
}

// NewCategoryID возвращает свободный идентификатор для своей категории.
func NewCategoryID(existing []profile.Category) string {
	for {
		var b [4]byte
		_, _ = rand.Read(b[:])
		id := "c-" + hex.EncodeToString(b[:])
		if findCategory(existing, id) < 0 {
			return id
		}
	}
}

func findCategory(cats []profile.Category, id string) int {
	for i, c := range cats {
		if c.ID == id {
			return i
		}
	}
	return -1
}

// ExportCategory сериализует свою категорию из списка в файл для передачи.
func ExportCategory(cats []profile.Category, id string) ([]byte, error) {
	i := findCategory(cats, id)
	if i < 0 {
		return nil, errors.New("категория не найдена")
	}
	return profile.ExportCategory(cats[i])
}

// ImportCategory читает файл категории и готовит её к добавлению в список.
// Направление в файле не хранится, его выбирает пользователь при импорте.
func ImportCategory(data []byte, action string, existing []profile.Category) (profile.Category, error) {
	c, err := profile.ParseCategoryFile(data)
	if err != nil {
		return profile.Category{}, err
	}
	switch action {
	case profile.ActionAuto, profile.ActionCorp, profile.ActionProxy, profile.ActionDirect, profile.ActionBlock:
	default:
		return profile.Category{}, fmt.Errorf("неизвестное направление %q", action)
	}
	c.Action = action
	c.ID = NewCategoryID(existing)
	c.Name = uniqueCategoryName(c.Name, existing)
	return c, nil
}

// uniqueCategoryName добавляет « (2)», « (3)»…, если такое название уже есть.
func uniqueCategoryName(name string, existing []profile.Category) string {
	taken := map[string]bool{}
	for _, c := range existing {
		taken[c.Name] = true
	}
	if !taken[name] {
		return name
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s (%d)", name, n)
		if !taken[candidate] {
			return candidate
		}
	}
}
