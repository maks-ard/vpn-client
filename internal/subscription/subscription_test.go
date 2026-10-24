package subscription

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const links = "vless://11111111-2222-3333-4444-555555555555@nl.example.com:443?security=reality&pbk=KEY&sni=www.microsoft.com&type=tcp&flow=xtls-rprx-vision#%F0%9F%87%B3%F0%9F%87%B1%20%D0%9D%D0%B8%D0%B4%D0%B5%D1%80%D0%BB%D0%B0%D0%BD%D0%B4%D1%8B\n" +
	"trojan://pass@tr.example.com:443#Trojan\n" +
	"vless://22222222-2222-3333-4444-555555555555@de.example.com:8443?security=tls&type=ws&path=%2Fws#Germany\n"

func TestParseBase64(t *testing.T) {
	h := http.Header{}
	h.Set("Subscription-Userinfo", "upload=100; download=200; total=1000; expire=1893456000")
	h.Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("Мой VPN")))
	sub, err := Parse([]byte(base64.StdEncoding.EncodeToString([]byte(links))), h)
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.Servers) != 2 || sub.Servers[0].Name != "🇳🇱 Нидерланды" || sub.Servers[1].Links[0].Transport != "ws" {
		t.Errorf("servers: %+v", sub.Servers)
	}
	if len(sub.Skipped) != 1 || !strings.HasPrefix(sub.Skipped[0], "trojan") {
		t.Errorf("skipped: %v", sub.Skipped)
	}
	if sub.Title != "Мой VPN" || sub.Upload != 100 || sub.Download != 200 || sub.Total != 1000 || sub.Expire.Year() != 2030 {
		t.Errorf("info: %+v", sub.Info)
	}
}

func TestParsePlainAndErrors(t *testing.T) {
	if sub, err := Parse([]byte(links), nil); err != nil || len(sub.Servers) != 2 {
		t.Errorf("plain: %v %v", sub, err)
	}
	for name, body := range map[string]string{
		"html":     "<!doctype html><html></html>",
		"пусто":    "",
		"мусор":    "%%%",
		"не vless": "trojan://a@b:1#x",
	} {
		if _, err := Parse([]byte(body), nil); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

func TestGetWithCache(t *testing.T) {
	fail := false
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.UserAgent()
		if fail {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(links))))
	}))
	defer srv.Close()
	dir := t.TempDir()

	sub, err := Get(context.Background(), srv.URL, "", dir)
	if err != nil || sub.FromCache || len(sub.Servers) != 2 {
		t.Fatalf("первый запрос: %+v, %v", sub, err)
	}
	if ua != DefaultUserAgent {
		t.Errorf("User-Agent = %q", ua)
	}

	fail = true
	sub, err = Get(context.Background(), srv.URL, "", dir)
	if err != nil || !sub.FromCache || sub.FetchError == nil || len(sub.Servers) != 2 || time.Since(sub.FetchedAt) > time.Minute {
		t.Fatalf("из кэша: %+v, %v", sub, err)
	}

	if _, err := Get(context.Background(), srv.URL, "", t.TempDir()); err == nil {
		t.Fatal("без кэша и сети ожидалась ошибка")
	}
}
