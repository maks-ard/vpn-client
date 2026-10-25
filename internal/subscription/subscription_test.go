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
	if len(sub.Skipped) != 1 || sub.Skipped[0] != "Trojan: trojan: протокол пока не поддерживается" {
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
		w.Header().Set("Subscription-Userinfo", "total=1000; expire=1893456000")
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

// Панель отдаёт срок и трафик только известным ей клиентам: для остальных
// заголовка нет, и мы дозапрашиваем его с их User-Agent.
func TestGetInfoUserAgentFallback(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.UserAgent())
		if strings.HasPrefix(r.UserAgent(), "Happ/") {
			w.Header().Set("Subscription-Userinfo", "upload=0; download=5; total=0; expire=1893456000")
		}
		_, _ = w.Write([]byte(links))
	}))
	defer srv.Close()

	sub, err := Get(context.Background(), srv.URL, "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if sub.Expire.Year() != 2030 || sub.Download != 5 || len(sub.Servers) != 2 {
		t.Errorf("info: %+v, серверов %d", sub.Info, len(sub.Servers))
	}
	if strings.Join(seen, ",") != DefaultUserAgent+",Happ/1.0" {
		t.Errorf("запросы: %v", seen)
	}

	// Панель без срока: перебор клиентов заканчивается, подписка работает.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(links)) }))
	defer srv2.Close()
	sub, err = Get(context.Background(), srv2.URL, "", t.TempDir())
	if err != nil || !sub.Expire.IsZero() || len(sub.Servers) != 2 {
		t.Errorf("без срока: %+v, %v", sub, err)
	}
}

// Панель с лимитом устройств присылает вместо серверов заглушку с причиной в
// названии. Причина показывается, а VPN работает по последнему рабочему
// списку: заглушка не должна затирать кэш.
func TestPanelNoticeKeepsCache(t *testing.T) {
	stub := `{"remarks":"Превышено кол-во устройств","outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]}`
	limited := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limited {
			_, _ = w.Write([]byte(stub))
			return
		}
		_, _ = w.Write([]byte(links))
	}))
	defer srv.Close()
	dir := t.TempDir()
	if _, err := Get(context.Background(), srv.URL, "", dir); err != nil {
		t.Fatal(err)
	}

	limited = true
	for range 2 {
		sub, err := Get(context.Background(), srv.URL, "", dir)
		if err != nil {
			t.Fatal(err)
		}
		if !sub.FromCache || len(sub.Servers) != 2 {
			t.Fatalf("ожидался кэш с 2 серверами: %+v", sub)
		}
		if sub.FetchError == nil || !strings.Contains(sub.FetchError.Error(), "Превышено кол-во устройств") {
			t.Fatalf("причина отказа не показана: %v", sub.FetchError)
		}
	}
}

func TestParseHysteria2(t *testing.T) {
	body := "hysteria2://pass@hy.example.com:443?obfs=salamander&obfs-password=x#Hysteria\n" +
		"hy2://pass@hy2.example.com:443,20000-30000#\n" +
		"hysteria2://hy.example.com:443#без пароля\n"
	sub, err := Parse([]byte(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.Servers) != 2 || sub.Servers[0].Name != "Hysteria" || sub.Servers[1].Name != "hy2.example.com" {
		t.Errorf("servers: %+v", sub.Servers)
	}
	if l := sub.Servers[1].Links[0]; l.Protocol != "hysteria2" || len(l.ServerPorts) != 2 {
		t.Errorf("link: %+v", l)
	}
	if len(sub.Skipped) != 1 || !strings.Contains(sub.Skipped[0], "пароля") {
		t.Errorf("skipped: %v", sub.Skipped)
	}
}

func TestSkippedFor(t *testing.T) {
	body := "vless://11111111-2222-3333-4444-555555555555@a.example.com:443?type=xhttp#%D0%A4%D0%B8%D0%BD%D0%BB%D1%8F%D0%BD%D0%B4%D0%B8%D1%8F\n" +
		"vless://11111111-2222-3333-4444-555555555555@b.example.com:443?type=xhttp\n" +
		"vless://22222222-2222-3333-4444-555555555555@de.example.com:8443?security=tls&type=ws&path=%2Fws#Germany\n"
	sub, err := Parse([]byte(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := sub.SkippedFor("Финляндия"); len(got) != 1 || !strings.Contains(got[0], "XHTTP") {
		t.Errorf("Финляндия: %v (всё: %v)", got, sub.Skipped)
	}
	if len(sub.Skipped) != 2 || sub.SkippedFor("Germany") != nil {
		t.Errorf("skipped: %v", sub.Skipped)
	}
}
