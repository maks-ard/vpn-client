package app

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// clash — минимальный клиент Clash API, который sing-box поднимает на
// 127.0.0.1 со случайным портом и секретом.
type clash struct {
	base   string
	secret string
	http   *http.Client
}

func newClash(addr, secret string) *clash {
	// Запросы к API не должны идти через системный прокси.
	transport := &http.Transport{Proxy: nil}
	return &clash{base: "http://" + addr, secret: secret, http: &http.Client{Transport: transport}}
}

func (c *clash) do(ctx context.Context, method, path string, body any, out any) error {
	var reader *strings.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(data))
	} else {
		reader = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Message == "" {
			e.Message = resp.Status
		}
		return fmt.Errorf("%s", e.Message)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *clash) ready(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/version", nil, nil)
}

type clashProxy struct {
	Type    string   `json:"type"`
	Now     string   `json:"now"`
	All     []string `json:"all"`
	History []struct {
		Delay int `json:"delay"`
	} `json:"history"`
}

func (p clashProxy) delay() int {
	if len(p.History) == 0 {
		return 0
	}
	return p.History[len(p.History)-1].Delay
}

func (c *clash) proxies(ctx context.Context) (map[string]clashProxy, error) {
	var out struct {
		Proxies map[string]clashProxy `json:"proxies"`
	}
	err := c.do(ctx, http.MethodGet, "/proxies", nil, &out)
	return out.Proxies, err
}

func (c *clash) selectProxy(ctx context.Context, selector, name string) error {
	return c.do(ctx, http.MethodPut, "/proxies/"+url.PathEscape(selector), map[string]string{"name": name}, nil)
}

// delay замеряет задержку через outbound и сохраняет её в истории sing-box.
func (c *clash) delay(ctx context.Context, name string) (int, error) {
	var out struct {
		Delay int `json:"delay"`
	}
	q := url.Values{"url": {"https://www.gstatic.com/generate_204"}, "timeout": {"5000"}}
	err := c.do(ctx, http.MethodGet, "/proxies/"+url.PathEscape(name)+"/delay?"+q.Encode(), nil, &out)
	return out.Delay, err
}

// groupDelay замеряет все серверы группы сразу.
func (c *clash) groupDelay(ctx context.Context, group string) error {
	q := url.Values{"url": {"https://www.gstatic.com/generate_204"}, "timeout": {"5000"}}
	return c.do(ctx, http.MethodGet, "/group/"+url.PathEscape(group)+"/delay?"+q.Encode(), nil, nil)
}

// dnsQuery резолвит имя по правилам DNS sing-box. Ошибка означает, что
// DNS-сервер недоступен (для корпоративного домена — туннель не поднят);
// NXDOMAIN — нормальный ответ.
func (c *clash) dnsQuery(ctx context.Context, name string) error {
	q := url.Values{"name": {name}, "type": {"A"}}
	return c.do(ctx, http.MethodGet, "/dns/query?"+q.Encode(), nil, nil)
}

type traffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// traffic читает поток /traffic (одна JSON-строка в секунду) до отмены ctx.
func (c *clash) traffic(ctx context.Context, fn func(traffic)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/traffic", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var t traffic
		if json.Unmarshal(sc.Bytes(), &t) == nil {
			fn(t)
		}
	}
	return sc.Err()
}

// waitReady ждёт, пока sing-box поднимет API.
func (c *clash) waitReady(ctx context.Context, timeout time.Duration, exited <-chan struct{}) error {
	deadline := time.Now().Add(timeout)
	for {
		reqCtx, cancel := context.WithTimeout(ctx, time.Second)
		err := c.ready(reqCtx)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("sing-box не запустился за %s", timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-exited:
			return fmt.Errorf("sing-box завершился при запуске")
		case <-time.After(200 * time.Millisecond):
		}
	}
}
