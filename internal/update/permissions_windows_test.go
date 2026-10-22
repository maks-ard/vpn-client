package update

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestReplaceExecutablePermissions(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "download.exe")
	installed := filepath.Join(dir, "vpnclient.exe")
	if err := os.WriteFile(source, []byte("тестовый exe"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Проверяем ACL установленного файла независимо от ACL источника.
	if err := Replace(installed, source); err != nil {
		t.Fatal(err)
	}
	got, err := windows.GetNamedSecurityInfo(installed, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.String(), "(A;;0x1200a9;;;BU)") && !strings.Contains(got.String(), "(A;;GRGX;;;BU)") {
		t.Fatalf("нет разрешения чтения и запуска пользователям: %s", got.String())
	}
}
