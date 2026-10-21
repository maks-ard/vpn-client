package runner

import "testing"

func TestParseVersion(t *testing.T) {
	v, err := parseVersion("sing-box version 1.14.3\n\nEnvironment: go1.25.5 windows/amd64\nTags: with_gvisor,with_openvpn\nRevision: abc\nCGO: disabled\n")
	if err != nil {
		t.Fatal(err)
	}
	if v.String() != "1.14.3" || !v.AtLeast(1, 14) || v.AtLeast(1, 15) {
		t.Errorf("версия разобрана неверно: %v", v)
	}
	if !v.HasTag("with_openvpn") || v.HasTag("with_tailscale") {
		t.Errorf("теги: %v", v.Tags)
	}
	if _, err := parseVersion("sing-box version unknown"); err == nil {
		t.Error("ожидалась ошибка для неизвестной версии")
	}
}
