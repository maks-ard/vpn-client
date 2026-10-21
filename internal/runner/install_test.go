package runner

import (
	"bytes"
	"os"
	"testing"
)

func TestInstall(t *testing.T) {
	dir := t.TempDir()
	data := []byte("fake sing-box binary")

	path, release, err := Install(dir, data)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if got, _ := os.ReadFile(path); !bytes.Equal(got, data) {
		t.Fatalf("содержимое не совпадает: %q", got)
	}

	// Подменённый файл должен быть перезаписан встроенным.
	if err := os.WriteFile(path, []byte("evil"), 0o755); err != nil {
		t.Fatal(err)
	}
	path2, release, err := Install(dir, data)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if got, _ := os.ReadFile(path2); path2 != path || !bytes.Equal(got, data) {
		t.Fatalf("файл не восстановлен: %q", got)
	}
}
