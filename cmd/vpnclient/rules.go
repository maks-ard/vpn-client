//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/maks-ard/vpn-client/internal/app"
	"github.com/maks-ard/vpn-client/internal/profile"
	"github.com/maks-ard/vpn-client/internal/singbox"
)

// categoryFileFilter — маска файлов категорий в диалогах.
const categoryFileFilter = "Категория правил (*.vpncat.json, *.json)"

// Explain говорит, куда пойдёт трафик к адресу при переданных настройках,
// в том числе ещё не применённых.
func (s *Service) Explain(settings app.Settings, target string) (singbox.Verdict, error) {
	ctx, cancel := s.call()
	defer cancel()
	return s.client.Explain(ctx, settings, target)
}

// ParseRule проверяет одно правило сразу при вводе. Пустой тип означает
// «определить по значению». Возвращает правило в нормализованном виде.
func (s *Service) ParseRule(ruleType, value string) (profile.Rule, error) {
	return profile.NormalizeRule(profile.Rule{Type: ruleType, Value: value})
}

// ImportCategoryFile открывает диалог выбора файла категории. existing —
// категории из окна (с несохранёнными правками): по ним подбирается
// свободное название. Возвращает nil, если пользователь передумал. Файл читается
// с правами пользователя; направление в файле не хранится и по умолчанию «auto».
func (s *Service) ImportCategoryFile(existing []profile.Category) (*profile.Category, error) {
	path, err := s.wapp.Dialog.OpenFile().
		SetTitle("Файл категории").
		AddFilter(categoryFileFilter, "*.json").
		AttachToWindow(s.window).
		PromptForSingleSelection()
	if err != nil || path == "" {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть файл: %w", err)
	}
	if info.Size() > profile.MaxCategoryFile {
		return nil, fmt.Errorf("файл больше %d КБ, это не файл категории", profile.MaxCategoryFile>>10)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать файл: %w", err)
	}
	c, err := app.ImportCategory(data, profile.ActionAuto, existing)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ExportCategoryFile сохраняет свою категорию в файл, который можно передать
// другому человеку. В файл попадают название и правила, но не направление.
func (s *Service) ExportCategoryFile(c profile.Category) error {
	data, err := profile.ExportCategory(c)
	if err != nil {
		return err
	}
	name := strings.Map(func(r rune) rune {
		if strings.ContainsRune(`<>:"/\|?*`, r) || r < ' ' {
			return '_'
		}
		return r
	}, c.Name)
	path, err := s.wapp.Dialog.SaveFile().
		SetMessage("Сохранить категорию").
		SetFilename(name+".vpncat.json").
		AddFilter(categoryFileFilter, "*.json").
		AttachToWindow(s.window).
		PromptForSingleSelection()
	if err != nil || path == "" {
		return err
	}
	if !strings.HasSuffix(strings.ToLower(path), ".json") {
		path += ".json"
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return errors.New("не удалось сохранить файл: " + err.Error())
	}
	return nil
}
