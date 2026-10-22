// Package update проверяет релизы на GitHub, скачивает новую версию с
// проверкой SHA-256 и подменяет установленный exe.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo — откуда брать релизы.
const Repo = "maks-ard/vpn-client"

type Release struct {
	Version string
	ExeURL  string
	SumURL  string
}

type Checker struct {
	// API — адрес GitHub API (подменяется в тестах).
	API  string
	Repo string
	Arch string
	HTTP *http.Client
	// Progress получает число загруженных байт exe и его размер (0 — неизвестен).
	Progress func(done, total int64)
}

func NewChecker() *Checker {
	return &Checker{
		API:  "https://api.github.com",
		Repo: Repo,
		Arch: runtime.GOARCH,
		HTTP: &http.Client{Timeout: 5 * time.Minute},
	}
}

// AssetName — имя exe в релизе (так его называет release.yml).
func AssetName(version, arch string) string {
	return fmt.Sprintf("vpnclient-%s-windows-%s.exe", version, arch)
}

// Latest возвращает последний опубликованный релиз.
func (c *Checker) Latest(ctx context.Context) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.API+"/repos/"+c.Repo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "vpn-client-updater")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub ответил %s", resp.Status)
	}
	var body struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return nil, err
	}
	rel := &Release{Version: body.TagName}
	exe := AssetName(body.TagName, c.Arch)
	for _, a := range body.Assets {
		switch a.Name {
		case exe:
			rel.ExeURL = a.URL
		case exe + ".sha256":
			rel.SumURL = a.URL
		}
	}
	if rel.ExeURL == "" || rel.SumURL == "" {
		return nil, fmt.Errorf("в релизе %s нет файла %s или его контрольной суммы", body.TagName, exe)
	}
	return rel, nil
}

// Download скачивает exe в dir и проверяет контрольную сумму. Возвращает
// путь к проверенному файлу.
func (c *Checker) Download(ctx context.Context, rel *Release, dir string) (string, error) {
	sumText, err := c.get(ctx, rel.SumURL, 1024)
	if err != nil {
		return "", fmt.Errorf("контрольная сумма: %w", err)
	}
	fields := strings.Fields(string(sumText))
	if len(fields) == 0 || len(fields[0]) != 64 {
		return "", errors.New("неверный файл контрольной суммы")
	}
	want, err := hex.DecodeString(fields[0])
	if err != nil {
		return "", errors.New("неверный файл контрольной суммы")
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, AssetName(rel.Version, c.Arch))
	tmp := path + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rel.ExeURL, nil)
	if err != nil {
		f.Close()
		return "", err
	}
	req.Header.Set("User-Agent", "vpn-client-updater")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		f.Close()
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		f.Close()
		return "", fmt.Errorf("загрузка: сервер ответил %s", resp.Status)
	}
	h := sha256.New()
	var w io.Writer = io.MultiWriter(f, h)
	if c.Progress != nil {
		w = io.MultiWriter(w, &progressWriter{total: max(resp.ContentLength, 0), fn: c.Progress})
	}
	_, err = io.Copy(w, io.LimitReader(resp.Body, 512<<20))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("загрузка: %w", err)
	}
	if got := h.Sum(nil); !equal(got, want) {
		return "", fmt.Errorf("контрольная сумма не совпала: файл повреждён или подменён")
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

type progressWriter struct {
	done, total int64
	fn          func(done, total int64)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	p.done += int64(len(b))
	p.fn(p.done, p.total)
	return len(b), nil
}

func (c *Checker) get(ctx context.Context, url string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vpn-client-updater")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("сервер ответил %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, max))
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Replace ставит newFile на место installed. Запущенный exe в Windows
// нельзя перезаписать, но можно переименовать: старый уходит в .old и
// удаляется при следующем обновлении.
func Replace(installed, newFile string) error {
	// Готовим файл рядом с установленным: перенос из ProgramData сохраняет
	// закрытый ACL и лишает обычное окно права читать и запускать exe.
	in, err := os.Open(newFile)
	if err != nil {
		return fmt.Errorf("подготовка exe: %w", err)
	}
	defer in.Close()
	f, err := os.CreateTemp(filepath.Dir(installed), ".vpnclient-*.exe")
	if err != nil {
		return fmt.Errorf("подготовка exe: %w", err)
	}
	staged := f.Name()
	defer os.Remove(staged)
	_, err = io.Copy(f, in)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = prepareExecutable(staged)
	}
	if err != nil {
		return fmt.Errorf("подготовка exe: %w", err)
	}
	old := installed + ".old"
	if err := os.Remove(old); err != nil && !errors.Is(err, os.ErrNotExist) {
		// Прошлая копия ещё запущена (например, окно старой версии) — отодвигаем
		// текущую под уникальным именем.
		old = fmt.Sprintf("%s.old-%d", installed, time.Now().UnixNano())
	}
	if err := os.Rename(installed, old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("замена exe: %w", err)
	}
	if err := os.Rename(staged, installed); err != nil {
		if rollbackErr := os.Rename(old, installed); rollbackErr != nil {
			return fmt.Errorf("замена exe: %v; откат не выполнен: %w", err, rollbackErr)
		}
		return fmt.Errorf("замена exe: %w", err)
	}
	return nil
}

// PrepareExecutable задаёт права запуска для подготовленного установщиком exe.
func PrepareExecutable(path string) error { return prepareExecutable(path) }

// Newer сообщает, что версия latest новее current. Сборки разработчика
// ("dev" и всё, что не похоже на vX.Y.Z) не обновляются.
func Newer(latest, current string) bool {
	l, ok1 := parse(latest)
	c, ok2 := parse(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// Valid — версия похожа на релизную vX.Y.Z.
func Valid(v string) bool {
	_, ok := parse(v)
	return ok
}

func parse(v string) ([3]int, bool) {
	var out [3]int
	v, ok := strings.CutPrefix(v, "v")
	if !ok {
		return out, false
	}
	v, _, _ = strings.Cut(v, "-")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
