package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/maks-ard/vpn-client/internal/singbox"
)

const (
	// ruleSetMaxAge — как долго файл rule-set считается свежим, как у update_interval в конфиге.
	ruleSetMaxAge  = 72 * time.Hour
	ruleSetMaxSize = 16 << 20
	// ruleSetPrepareTimeout — сколько подключение ждёт скачивания наборов категорий.
	ruleSetPrepareTimeout = 25 * time.Second
)

// Explain говорит, куда пойдёт трафик к адресу при переданных настройках
// (в том числе ещё не применённых). Подписку не качает: берёт сохранённую
// копию серверов. Состав готовых наборов проверяет сам sing-box.
func (m *Manager) Explain(ctx context.Context, settings Settings, target string) (singbox.Verdict, error) {
	if err := settings.normalize(); err != nil {
		return singbox.Verdict{}, err
	}
	prof, err := settings.profile(m.paths)
	if err != nil {
		return singbox.Verdict{}, err
	}
	in, err := singbox.FromProfileOffline(prof, m.paths.Data)
	if err != nil {
		return singbox.Verdict{}, err
	}
	exe, release, err := m.singBox()
	if err != nil {
		// Без sing-box остаётся проверка по спискам: наборы будут пропущены.
		return singbox.Explain(in, target, nil)
	}
	defer release()
	return singbox.Explain(in, target, m.setMatcher(ctx, exe))
}

func (m *Manager) setMatcher(ctx context.Context, exe string) singbox.SetMatcher {
	return func(tag, url, target string) (bool, error) {
		if url == "" {
			return false, fmt.Errorf("неизвестный набор %s", tag)
		}
		path, err := m.ruleSetFile(ctx, exe, url)
		if err != nil {
			return false, err
		}
		cmd := exec.CommandContext(ctx, exe, "rule-set", "match", "-f", "binary", path, target)
		// sing-box печатает результат в stderr, поэтому читаем оба потока.
		out, err := cmd.CombinedOutput()
		text := strings.TrimSpace(string(out))
		if err != nil {
			if text != "" {
				return false, errors.New(text)
			}
			return false, err
		}
		return strings.HasPrefix(text, "match"), nil
	}
}

// ruleSetFile возвращает путь к локальной копии rule-set, скачивая её при
// отсутствии или устаревании. Скачанное проверяется самим sing-box (exe), чтобы
// страница-заглушка вместо .srs не попала в конфиг и не сломала запуск. Если
// обновить не вышло, а старая копия есть, берётся она.
func (m *Manager) ruleSetFile(ctx context.Context, exe, url string) (string, error) {
	sum := sha256.Sum256([]byte(url))
	path := filepath.Join(m.paths.Data, "rule-sets", hex.EncodeToString(sum[:8])+".srs")
	info, statErr := os.Stat(path)
	if statErr == nil && time.Since(info.ModTime()) < ruleSetMaxAge {
		return path, nil
	}
	fetch := m.fetchSet
	if fetch == nil {
		fetch = httpFetchSet
	}
	data, err := fetch(ctx, url)
	if err == nil {
		err = validateRuleSet(ctx, exe, data, filepath.Dir(path))
	}
	if err != nil {
		if statErr == nil {
			return path, nil
		}
		return "", fmt.Errorf("не удалось получить набор: %w", err)
	}
	if err := writeFileAtomic(path, data); err != nil {
		return "", err
	}
	return path, nil
}

// validateRuleSet просит sing-box открыть набор: если файл не rule-set, команда
// завершится с ошибкой. Без exe проверка пропускается.
func validateRuleSet(ctx context.Context, exe string, data []byte, dir string) error {
	if exe == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "check-*.srs")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, exe, "rule-set", "match", "-f", "binary", tmp.Name(), "example.com").CombinedOutput()
	if err != nil {
		return fmt.Errorf("файл не похож на набор .srs: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// prepareRuleSets скачивает и проверяет наборы активных категорий до сборки
// конфига. Набор, который получить не удалось, в результат не попадает, и
// категория пропускается с предупреждением. Подключение из-за этого не
// откладывается дольше ruleSetPrepareTimeout.
func (m *Manager) prepareRuleSets(ctx context.Context, exe string, in *singbox.Input) map[string]string {
	paths := map[string]string{}
	refs := in.CategorySets()
	if len(refs) == 0 {
		return paths
	}
	ctx, cancel := context.WithTimeout(ctx, ruleSetPrepareTimeout)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, ref := range refs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			path, err := m.ruleSetFile(ctx, exe, ref.URL)
			if err != nil {
				m.log.Printf("набор %s: %v", ref.Tag, err)
				return
			}
			mu.Lock()
			paths[ref.Tag] = path
			mu.Unlock()
		}()
	}
	wg.Wait()
	return paths
}

func httpFetchSet(ctx context.Context, url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, errors.New("ожидается ссылка https://")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("сервер ответил %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, ruleSetMaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > ruleSetMaxSize {
		return nil, fmt.Errorf("файл больше %d МБ", ruleSetMaxSize>>20)
	}
	return data, nil
}
