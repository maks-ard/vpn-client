package winsvc

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-ole/go-ole"
)

func TestPrepareInstallCopy(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ProgramFiles", root)
	if err := os.MkdirAll(InstallDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source.exe")
	if err := os.WriteFile(source, []byte("test executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := prepareInstallCopy(source)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "test executable" {
		t.Fatalf("копия: %q, %v", got, err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("исходный файл потерян: %v", err)
	}
	if _, err := os.Stat(path + ".old"); !os.IsNotExist(err) {
		t.Fatalf("остался временный файл: %v", err)
	}
	if _, err := prepareInstallCopy(filepath.Join(root, "missing.exe")); err == nil {
		t.Fatal("отсутствующий источник принят")
	}
	files, err := os.ReadDir(InstallDir())
	if err != nil || len(files) != 1 {
		t.Fatalf("мусор после ошибки: %v, %v", files, err)
	}
}

func TestCreateShortcutWithInitializedCOM(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil && !isCOMInitialized(err) {
		t.Fatal(err)
	}
	defer ole.CoUninitialize()
	root := t.TempDir()
	path := filepath.Join(root, "vpn-client.lnk")
	if err := createShortcutAt(filepath.Join(root, "vpnclient.exe"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if err := createShortcutAt(filepath.Join(root, "vpnclient.exe"), filepath.Join(root, "missing", "vpn-client.lnk")); err == nil {
		t.Fatal("ошибка сохранения ярлыка скрыта")
	}
}
