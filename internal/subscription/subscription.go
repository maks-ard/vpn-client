// Package subscription скачивает и разбирает подписки (Remnawave, Marzban,
// 3x-ui и т.п.): по https-ссылке сервер отдаёт список ссылок vless://,
// обычно в base64, а в заголовках — название, остаток трафика и срок.
package subscription

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/maks-ard/vpn-client/internal/vless"
)

// DefaultUserAgent: панели выбирают формат ответа по User-Agent, и для
// v2rayN все они отдают base64 со ссылками, который мы умеем разбирать.
const DefaultUserAgent = "v2rayN/7.0"

const maxBody = 4 << 20

type Info struct {
	Title    string    `json:"title,omitempty"`
	Upload   int64     `json:"upload,omitempty"`
	Download int64     `json:"download,omitempty"`
	Total    int64     `json:"total,omitempty"` // 0 — без лимита
	Expire   time.Time `json:"expire,omitempty"`
}

type Subscription struct {
	Info
	Servers []*vless.Link
	// Skipped — строки, которые не удалось использовать (другой протокол и т.п.).
	Skipped []string
	// FetchedAt — когда список был получен с сервера.
	FetchedAt time.Time
	// FromCache — сервер недоступен, использован сохранённый список.
	FromCache bool
	// FetchError — почему не удалось обновить список (если FromCache).
	FetchError error
}

// cached — то, что сохраняется на диск между запусками.
type cached struct {
	FetchedAt time.Time   `json:"fetched_at"`
	Header    http.Header `json:"header"`
	Body      []byte      `json:"body"`
}

// Get скачивает подписку, а если это не удалось — берёт последнюю
// сохранённую копию из cacheDir. Так VPN поднимается, даже когда сайт
// подписки недоступен.
func Get(ctx context.Context, url, userAgent, cacheDir string) (*Subscription, error) {
	cachePath := filepath.Join(cacheDir, "subscription.json")
	header, body, err := fetch(ctx, url, userAgent)
	if err == nil {
		sub, perr := Parse(body, header)
		if perr == nil {
			sub.FetchedAt = time.Now()
			_ = save(cachePath, cached{FetchedAt: sub.FetchedAt, Header: header, Body: body})
			return sub, nil
		}
		err = perr
	}
	c, cerr := load(cachePath)
	if cerr != nil {
		return nil, fmt.Errorf("подписка: %w", err)
	}
	sub, perr := Parse(c.Body, c.Header)
	if perr != nil {
		return nil, fmt.Errorf("подписка: %w", err)
	}
	sub.FetchedAt = c.FetchedAt
	sub.FromCache = true
	sub.FetchError = err
	return sub, nil
}

func fetch(ctx context.Context, url, userAgent string) (http.Header, []byte, error) {
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("сервер подписки ответил %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, nil, err
	}
	return resp.Header, body, nil
}

// Parse разбирает тело ответа подписки и её заголовки.
func Parse(body []byte, header http.Header) (*Subscription, error) {
	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "<") {
		return nil, errors.New("вместо подписки пришла веб-страница; проверьте ссылку")
	}
	if isJSON(text) {
		links, skipped, err := parseXrayJSON(text)
		if err != nil {
			return nil, err
		}
		return finish(&Subscription{Info: parseInfo(header), Skipped: skipped}, links)
	}
	if !strings.Contains(text, "://") {
		decoded, err := decodeBase64(text)
		if err != nil {
			return nil, errors.New("неизвестный формат подписки")
		}
		text = string(decoded)
	}

	sub := &Subscription{Info: parseInfo(header)}
	var links []*vless.Link
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "vless://") {
			scheme, _, ok := strings.Cut(line, "://")
			if !ok || len(scheme) > 20 {
				scheme = "строка"
			}
			sub.Skipped = append(sub.Skipped, scheme+": протокол пока не поддерживается")
			continue
		}
		link, err := vless.Parse(line)
		if err != nil {
			sub.Skipped = append(sub.Skipped, err.Error())
			continue
		}
		links = append(links, link)
	}
	return finish(sub, links)
}

// finish даёт серверам уникальные имена (они становятся тегами в sing-box)
// и проверяет, что хоть один сервер есть.
func finish(sub *Subscription, links []*vless.Link) (*Subscription, error) {
	names := map[string]int{}
	for _, link := range links {
		if link.Name == "" {
			link.Name = link.Server
		}
		if n := names[link.Name]; n > 0 {
			names[link.Name]++
			link.Name = fmt.Sprintf("%s (%d)", link.Name, n+1)
		} else {
			names[link.Name] = 1
		}
		sub.Servers = append(sub.Servers, link)
	}
	if len(sub.Servers) == 0 {
		if len(sub.Skipped) > 0 {
			return nil, fmt.Errorf("в подписке нет подходящих серверов: %s", strings.Join(sub.Skipped, "; "))
		}
		return nil, errors.New("подписка пуста")
	}
	return sub, nil
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("не base64")
}

// parseInfo читает стандартные заголовки подписок:
// subscription-userinfo: upload=1; download=2; total=3; expire=1700000000
// profile-title: base64:0J3QsNC30LLQsNC90LjQtQ==
func parseInfo(h http.Header) Info {
	var info Info
	if h == nil {
		return info
	}
	for _, part := range strings.Split(h.Get("Subscription-Userinfo"), ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upload":
			info.Upload = n
		case "download":
			info.Download = n
		case "total":
			info.Total = n
		case "expire":
			if n > 0 {
				info.Expire = time.Unix(n, 0)
			}
		}
	}
	title := h.Get("Profile-Title")
	if b64, ok := strings.CutPrefix(title, "base64:"); ok {
		if b, err := decodeBase64(b64); err == nil {
			title = string(b)
		}
	}
	info.Title = title
	return info
}

// FetchInfo получает метаданные независимо от запуска туннеля. Ответ не
// сохраняется: профиль может содержать ключи и другие секреты.
func FetchInfo(ctx context.Context, link string) (Info, error) {
	h, _, err := fetch(ctx, link, "")
	if err != nil {
		return Info{}, err
	}
	return parseInfo(h), nil
}

func save(path string, c cached) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func load(path string) (cached, error) {
	var c cached
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	err = json.NewDecoder(bytes.NewReader(data)).Decode(&c)
	return c, err
}
