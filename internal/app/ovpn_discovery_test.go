package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindOVPN(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.ovpn", "b.OVPN", "ignore.txt", "nested/c.conf", "nested/deep/hidden.ovpn"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := FindOVPN([]string{root, root, filepath.Join(root, "missing")})
	if len(got) != 3 {
		t.Fatalf("ожидалось 3 профиля: %v", got)
	}
}
