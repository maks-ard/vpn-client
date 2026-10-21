package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v0.2.0", "v0.1.9", true},
		{"v0.1.10", "v0.1.9", true},
		{"v1.0.0", "v0.9.9", true},
		{"v0.1.3", "v0.1.3", false},
		{"v0.1.2", "v0.1.3", false},
		{"v0.2.0", "dev", false},
		{"garbage", "v0.1.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.latest, c.current); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.latest, c.current, got)
		}
	}
}

func fakeGitHub(t *testing.T, exe []byte, sum string) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v0.2.0","assets":[
				{"name":"vpnclient-v0.2.0-windows-amd64.exe","browser_download_url":"%[1]s/exe"},
				{"name":"vpnclient-v0.2.0-windows-amd64.exe.sha256","browser_download_url":"%[1]s/sum"},
				{"name":"vpnclient-v0.2.0-windows-arm64.exe","browser_download_url":"%[1]s/arm"}]}`, srv.URL)
		case "/exe":
			_, _ = w.Write(exe)
		case "/sum":
			fmt.Fprintf(w, "%s  vpnclient-v0.2.0-windows-amd64.exe\n", sum)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLatestAndDownload(t *testing.T) {
	exe := []byte("new binary")
	h := sha256.Sum256(exe)
	srv := fakeGitHub(t, exe, hex.EncodeToString(h[:]))
	c := &Checker{API: srv.URL, Repo: "o/r", Arch: "amd64", HTTP: srv.Client()}

	rel, err := c.Latest(context.Background())
	if err != nil || rel.Version != "v0.2.0" || !strings.HasSuffix(rel.ExeURL, "/exe") {
		t.Fatalf("latest: %+v %v", rel, err)
	}
	dir := t.TempDir()
	path, err := c.Download(context.Background(), rel, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(exe) {
		t.Errorf("содержимое: %q", got)
	}

	// Подмена файла ловится по контрольной сумме.
	bad := fakeGitHub(t, []byte("evil"), hex.EncodeToString(h[:]))
	c.API = bad.URL
	rel, _ = c.Latest(context.Background())
	if _, err := c.Download(context.Background(), rel, t.TempDir()); err == nil || !strings.Contains(err.Error(), "контрольная сумма") {
		t.Errorf("ожидалась ошибка контрольной суммы, получено %v", err)
	}

	c.Arch = "386"
	c.API = srv.URL
	if _, err := c.Latest(context.Background()); err == nil {
		t.Error("для архитектуры без файла ожидалась ошибка")
	}
}

func TestReplace(t *testing.T) {
	dir := t.TempDir()
	installed := filepath.Join(dir, "vpnclient.exe")
	newFile := filepath.Join(dir, "new.exe")
	_ = os.WriteFile(installed, []byte("old"), 0o755)
	_ = os.WriteFile(installed+".old", []byte("older"), 0o755)
	_ = os.WriteFile(newFile, []byte("new"), 0o755)
	if err := Replace(installed, newFile); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(installed); string(got) != "new" {
		t.Errorf("installed = %q", got)
	}
	if got, _ := os.ReadFile(installed + ".old"); string(got) != "old" {
		t.Errorf(".old = %q", got)
	}
	// .old занят (в Windows — запущенный файл): текущая копия уходит под
	// уникальное имя. Здесь занятость имитируем каталогом с содержимым.
	_ = os.Remove(installed + ".old")
	_ = os.MkdirAll(filepath.Join(installed+".old", "busy"), 0o755)
	_ = os.WriteFile(newFile, []byte("newer"), 0o755)
	if err := Replace(installed, newFile); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(installed); string(got) != "newer" {
		t.Errorf("installed = %q", got)
	}

	// Ошибка — старая версия остаётся на месте.
	if err := Replace(installed, filepath.Join(dir, "missing.exe")); err == nil {
		t.Error("ожидалась ошибка")
	}
	if got, _ := os.ReadFile(installed); string(got) != "newer" {
		t.Errorf("после отката installed = %q", got)
	}
}
