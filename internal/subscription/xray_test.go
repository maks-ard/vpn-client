package subscription

import (
	"strings"
	"testing"
)

// Подписка в формате Xray JSON, как её отдаёт Remnawave: отдельный конфиг на
// сервер плюс балансировщик «Авто». Адреса и ключи выдуманные.
const xraySub = `[
 {"remarks":"⚡ Авто","dns":{"hosts":{"rmn-nl":"203.0.113.10","rmn-de":["203.0.113.20","203.0.113.21"]}},
  "outbounds":[
   {"tag":"nl","protocol":"vless","settings":{"vnext":[{"address":"rmn-nl","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision","encryption":"none"}]}]},
    "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.microsoft.com","fingerprint":"chrome","publicKey":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","shortId":"ab12"}}},
   {"tag":"de","protocol":"vless","settings":{"vnext":[{"address":"rmn-de","port":8443,"users":[{"id":"22222222-2222-2222-2222-222222222222","encryption":"none"}]}]},
    "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"de.example.com","alpn":["http/1.1"]},"wsSettings":{"path":"/ws","headers":{"Host":"de.example.com"}}}},
   {"tag":"extra","protocol":"vless","settings":{"address":"198.51.100.5","port":443,"id":"33333333-3333-3333-3333-333333333333","encryption":"none"},
    "streamSettings":{"network":"grpc","security":"reality","realitySettings":{"serverName":"a.com","password":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"},"grpcSettings":{"serviceName":"svc"}}},
   {"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],
  "routing":{"balancers":[{"tag":"auto","selector":["nl","de","extra"]}]}},
 {"remarks":"🇳🇱 Нидерланды","dns":{"hosts":{"rmn-nl":"203.0.113.10"}},
  "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"rmn-nl","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision","encryption":"none"}]}]},
    "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.microsoft.com","fingerprint":"chrome","publicKey":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","shortId":"ab12"}}},
   {"tag":"direct","protocol":"freedom"}]},
 {"remarks":"🇩🇪 Германия","dns":{"hosts":{"rmn-de":["203.0.113.20"]}},
  "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"rmn-de","port":8443,"users":[{"id":"22222222-2222-2222-2222-222222222222","encryption":"none"}]}]},
    "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"de.example.com","alpn":["http/1.1"]},"wsSettings":{"path":"/ws","headers":{"Host":"de.example.com"}}}}]},
 {"remarks":"🇫🇮 Финляндия XHTTP",
  "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"fi.example.com","port":443,"users":[{"id":"44444444-4444-4444-4444-444444444444","encryption":"none"}]}]},
    "streamSettings":{"network":"xhttp","security":"tls"}}]},
 {"remarks":"Trojan","outbounds":[{"tag":"proxy","protocol":"trojan","settings":{}}]}
]`

func TestParseXrayJSON(t *testing.T) {
	sub, err := Parse([]byte(xraySub), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range sub.Servers {
		names = append(names, s.Name)
	}
	// Одиночные конфиги идут первыми под своими именами, из балансировщика
	// добавляется только сервер, которого нет отдельно.
	if strings.Join(names, ",") != "🇳🇱 Нидерланды,🇩🇪 Германия,extra" {
		t.Fatalf("серверы: %q", names)
	}
	nl, de, extra := sub.Servers[0], sub.Servers[1], sub.Servers[2]
	if nl.Server != "203.0.113.10" || nl.Port != 443 || nl.Security != "reality" || nl.PublicKey != "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0" ||
		nl.ShortID != "ab12" || nl.SNI != "www.microsoft.com" || nl.Flow != "xtls-rprx-vision" || nl.Fingerprint != "chrome" {
		t.Errorf("NL: %+v", nl)
	}
	if de.Server != "203.0.113.20" || de.Transport != "ws" || de.Path != "/ws" || de.Host != "de.example.com" ||
		de.SNI != "de.example.com" || de.Security != "tls" || len(de.ALPN) != 1 {
		t.Errorf("DE: %+v", de)
	}
	if extra.Server != "198.51.100.5" || extra.Transport != "grpc" || extra.ServiceName != "svc" || extra.PublicKey != "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0" {
		t.Errorf("extra (плоский формат, password): %+v", extra)
	}
	joined := strings.Join(sub.Skipped, "\n")
	if !strings.Contains(joined, "XHTTP") || !strings.Contains(joined, "trojan") {
		t.Errorf("skipped: %v", sub.Skipped)
	}
}

func TestParseXrayJSONSingleObject(t *testing.T) {
	sub, err := Parse([]byte(`{"remarks":"One","outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"one.example.com","port":443,"users":[{"id":"55555555-5555-5555-5555-555555555555"}]}]},"streamSettings":{"security":"tls"}}]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.Servers) != 1 || sub.Servers[0].Name != "One" || sub.Servers[0].SNI != "one.example.com" {
		t.Errorf("servers: %+v", sub.Servers[0])
	}
	if _, err := Parse([]byte(`[{"remarks":"x","outbounds":[{"protocol":"trojan"}]}]`), nil); err == nil {
		t.Error("без VLESS ожидалась ошибка")
	}
	if _, err := Parse([]byte(`[{"broken"`), nil); err == nil {
		t.Error("ожидалась ошибка разбора")
	}
}
