package singbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/maks-ard/vpn-client/internal/profile"
	"github.com/maks-ard/vpn-client/internal/subscription"
	"github.com/maks-ard/vpn-client/internal/vless"
)

const goldenVLESS = "vless://11111111-2222-3333-4444-555555555555@vless.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123456789abcdef&type=tcp#test"

// TestGoldenLegacyRouting фиксирует конфиг для профилей без категорий:
// после появления категорий маршрутизация у тех, кто их не настраивал,
// не должна измениться ни на байт. Эталоны обновляются только осознанно:
// UPDATE_GOLDEN=1 go test ./internal/singbox
func TestGoldenLegacyRouting(t *testing.T) {
	cases := []struct {
		name    string
		profile string
		vless   bool
		ovpn    bool
	}{
		{"vless-russia", "vless: \"" + goldenVLESS + "\"\n", true, false},
		{"vless-no-russia", "vless: \"" + goldenVLESS + "\"\nrouting:\n  russia_direct: false\n", true, false},
		{"ovpn-corp", "openvpn:\n  config: corp.ovpn\n  username: u\n  password: p\ncorporate:\n  domains: [corp.example.com]\n", false, true},
		{"both-russia", "vless: \"" + goldenVLESS + "\"\nopenvpn:\n  config: corp.ovpn\n  username: u\n  password: p\ncorporate:\n  domains: [corp.example.com, office.example]\n", true, true},
		{"both-no-russia", "vless: \"" + goldenVLESS + "\"\nopenvpn:\n  config: corp.ovpn\n  username: u\n  password: p\ncorporate:\n  domains: [corp.example.com]\nrouting:\n  russia_direct: false\n", true, true},
		{"full", "vless: \"" + goldenVLESS + "\"\nopenvpn:\n  config: corp.ovpn\n  username: u\n  password: p\ncorporate:\n  domains: [corp.example.com]\n  subnets: [10.10.0.0/16]\nrouting:\n  proxy_domains: [example.ru]\n  direct_domains: [example.com]\n  direct_processes: [qbittorrent.exe]\n", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := profile.Parse([]byte(c.profile), "testdata")
			if err != nil {
				t.Fatal(err)
			}
			in := &Input{Profile: p}
			if c.vless {
				link, err := vless.Parse(goldenVLESS)
				if err != nil {
					t.Fatal(err)
				}
				in.Servers = []subscription.Server{{Name: link.Name, Links: []*vless.Link{link}}}
			}
			if c.ovpn {
				if in.OpenVPN, err = loadOVPN(p); err != nil {
					t.Fatal(err)
				}
			}
			got, err := Build(in)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "golden", c.name+".json")
			if os.Getenv("UPDATE_GOLDEN") != "" {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("нет эталона %s (UPDATE_GOLDEN=1 go test ./internal/singbox): %v", path, err)
			}
			if string(got) != string(want) {
				t.Errorf("конфиг %s отличается от эталона %s", c.name, path)
			}
		})
	}
}
