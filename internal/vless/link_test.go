package vless

import "testing"

func TestParseReality(t *testing.T) {
	l, err := Parse("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:8443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=firefox&pbk=PUB&sid=ab&type=tcp&headerType=none#%D0%A1%D0%B5%D1%80%D0%B2%D0%B5%D1%80")
	if err != nil {
		t.Fatal(err)
	}
	if l.Server != "1.2.3.4" || l.Port != 8443 || l.UUID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("адрес/uuid: %+v", l)
	}
	if l.Security != "reality" || l.PublicKey != "PUB" || l.ShortID != "ab" || l.SNI != "www.microsoft.com" || l.Fingerprint != "firefox" {
		t.Errorf("reality: %+v", l)
	}
	if l.Flow != "xtls-rprx-vision" || l.Transport != "tcp" || l.Name != "Сервер" {
		t.Errorf("flow/transport/name: %+v", l)
	}
}

func TestParseWS(t *testing.T) {
	l, err := Parse("vless://id@cdn.example.com?security=tls&type=ws&path=%2Fws%3Fed%3D2048&host=front.example.com&alpn=h2,http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	if l.Port != 443 || l.Transport != "ws" || l.Path != "/ws?ed=2048" || l.Host != "front.example.com" {
		t.Errorf("ws: %+v", l)
	}
	if l.SNI != "cdn.example.com" {
		t.Errorf("SNI по умолчанию должен быть хостом сервера, получено %q", l.SNI)
	}
	if len(l.ALPN) != 2 {
		t.Errorf("alpn = %v", l.ALPN)
	}
}

func TestParseErrors(t *testing.T) {
	for _, link := range []string{
		"vmess://abc",
		"vless://@host:443",
		"vless://id@host:443?security=reality",
		"vless://id@host:443?type=xhttp",
		"vless://id@host:443?type=ws&flow=xtls-rprx-vision",
		"vless://id@host:443?encryption=mlkem768x25519plus",
		"vless://id@host:0",
	} {
		if _, err := Parse(link); err == nil {
			t.Errorf("%s: ожидалась ошибка", link)
		}
	}
}
