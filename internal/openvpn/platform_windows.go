package openvpn

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// platformArgs: без консоли OpenVPN узнаёт о Ctrl+Break только при следующем
// пробуждении цикла событий, и остановка затягивается. С --service он ждёт
// событие, которое обработчик Ctrl+Break взводит сразу, как у OpenVPN GUI.
func platformArgs() []string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return []string{"--service", "vpn-client-openvpn-" + hex.EncodeToString(b), "0"}
}

// Find ищет openvpn.exe из OpenVPN Community: путь из реестра, который
// записывает установщик, затем папку по умолчанию.
func Find() (string, error) {
	var candidates []string
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\OpenVPN`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		if exe, _, err := k.GetStringValue("exe_path"); err == nil && exe != "" {
			candidates = append(candidates, exe)
		}
		if dir, _, err := k.GetStringValue(""); err == nil && dir != "" {
			candidates = append(candidates, filepath.Join(dir, "bin", "openvpn.exe"))
		}
		k.Close()
	}
	if pf := os.Getenv("ProgramFiles"); pf != "" {
		candidates = append(candidates, filepath.Join(pf, "OpenVPN", "bin", "openvpn.exe"))
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", ErrNotFound
}
