// Package app — логика приложения без привязки к GUI: настройки,
// подключение и отключение, статус для окна и трея.
package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/maks-ard/vpn-client/internal/ovpn"
	"github.com/maks-ard/vpn-client/internal/profile"
)

// Settings — то, что пользователь меняет в окне настроек.
type Settings struct {
	// Link — ссылка на подписку (https://…) или на один сервер (vless://…).
	Link string `json:"link"`
	// Server — выбранный сервер подписки; пусто — самый быстрый.
	Server string `json:"server"`

	OVPNUsername string   `json:"ovpnUsername"`
	OVPNPassword string   `json:"ovpnPassword"`
	CorpDomains  []string `json:"corpDomains"`

	RussiaDirect   bool `json:"russiaDirect"`
	Autostart      bool `json:"autostart"`
	ConnectOnStart bool `json:"connectOnStart"`
	CloseToTray    bool `json:"closeToTray"`
}

// OVPNInfo — что показать в настройках про загруженный .ovpn.
type OVPNInfo struct {
	Loaded    bool   `json:"loaded"`
	Name      string `json:"name"`
	Server    string `json:"server"`
	NeedsAuth bool   `json:"needsAuth"`
	Error     string `json:"error,omitempty"`
}

func defaultSettings() Settings {
	return Settings{
		CorpDomains:  []string{"corp.example.com"},
		RussiaDirect: true,
		CloseToTray:  true,
	}
}

// Paths — где приложение хранит файлы.
type Paths struct {
	// Config — настройки и .ovpn.
	Config string
	// Data — sing-box, кэш подписки.
	Data string
	// Logs — каталог журнала; пусто — Data.
	Logs string
}

func DefaultPaths() (Paths, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return Paths{}, err
	}
	data, err := os.UserCacheDir()
	if err != nil {
		return Paths{}, err
	}
	return Paths{Config: filepath.Join(cfg, "vpn-client"), Data: filepath.Join(data, "vpn-client")}, nil
}

func (p Paths) settingsFile() string { return filepath.Join(p.Config, "settings.json") }
func (p Paths) ovpnFile() string     { return filepath.Join(p.Config, "corp.ovpn") }
func (p Paths) ovpnNameFile() string { return filepath.Join(p.Config, "corp.ovpn.name") }
func (p Paths) LogFile() string {
	if p.Logs != "" {
		return filepath.Join(p.Logs, "vpnclient.log")
	}
	return filepath.Join(p.Data, "vpnclient.log")
}

func loadSettings(p Paths) (Settings, error) {
	s := defaultSettings()
	data, err := os.ReadFile(p.settingsFile())
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return defaultSettings(), fmt.Errorf("настройки повреждены: %w", err)
	}
	return s, nil
}

func saveSettings(p Paths, s Settings) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(p.settingsFile(), data)
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// normalize чистит ввод пользователя.
func (s *Settings) normalize() error {
	s.Link = strings.TrimSpace(s.Link)
	switch {
	case s.Link == "":
	case strings.HasPrefix(s.Link, "vless://"):
		s.Server = ""
	case strings.HasPrefix(s.Link, "https://"), strings.HasPrefix(s.Link, "http://"):
	default:
		return errors.New("ссылка должна начинаться с https:// (подписка) или vless:// (один сервер)")
	}
	var domains []string
	seen := map[string]bool{}
	for _, d := range s.CorpDomains {
		d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
		d = strings.TrimPrefix(d, "*.")
		if d == "" || seen[d] {
			continue
		}
		if strings.ContainsAny(d, " /:@") || !strings.Contains(d, ".") {
			return fmt.Errorf("%q не похоже на домен", d)
		}
		seen[d] = true
		domains = append(domains, d)
	}
	s.CorpDomains = domains
	return nil
}

// profile собирает профиль для генератора конфига.
func (s Settings) profile(p Paths) (*profile.Profile, error) {
	prof := &profile.Profile{}
	switch {
	case strings.HasPrefix(s.Link, "vless://"):
		prof.VLESS = s.Link
	case s.Link != "":
		prof.Subscription = &profile.Subscription{URL: s.Link, Server: s.Server}
	}
	if _, err := os.Stat(p.ovpnFile()); err == nil {
		prof.OpenVPN = &profile.OpenVPN{Config: p.ovpnFile(), Username: s.OVPNUsername, Password: s.OVPNPassword}
		prof.Corporate.Domains = s.CorpDomains
	}
	rd := s.RussiaDirect
	prof.Routing.RussiaDirect = &rd
	if err := prof.Normalize(p.Config); err != nil {
		if prof.VLESS == "" && prof.Subscription == nil && prof.OpenVPN == nil {
			return nil, errors.New("укажите ссылку на подписку или загрузите файл .ovpn в настройках")
		}
		return nil, err
	}
	return prof, nil
}

// PrepareOVPN читает .ovpn, проверяет его и встраивает в него ключи из
// соседних файлов. Вызывается на стороне окна: у службы может не быть
// доступа к папке пользователя, и исходный файл может потом переехать.
func PrepareOVPN(src string) (name string, data []byte, err error) {
	raw, err := os.ReadFile(src)
	if err != nil {
		return "", nil, err
	}
	cfg, err := ovpn.ParseFile(src)
	if err != nil {
		return "", nil, err
	}
	return filepath.Base(src), inlineOVPN(raw, cfg), nil
}

// importOVPN сохраняет подготовленный (самодостаточный) .ovpn.
func importOVPN(p Paths, name string, data []byte) (OVPNInfo, error) {
	if _, err := ovpn.Parse(bytes.NewReader(data), ""); err != nil {
		return OVPNInfo{}, err
	}
	if err := writeFileAtomic(p.ovpnFile(), data); err != nil {
		return OVPNInfo{}, err
	}
	if err := writeFileAtomic(p.ovpnNameFile(), []byte(filepath.Base(name))); err != nil {
		return OVPNInfo{}, err
	}
	return ovpnInfo(p), nil
}

func removeOVPN(p Paths) error {
	_ = os.Remove(p.ovpnNameFile())
	err := os.Remove(p.ovpnFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func ovpnInfo(p Paths) OVPNInfo {
	if _, err := os.Stat(p.ovpnFile()); err != nil {
		return OVPNInfo{}
	}
	info := OVPNInfo{Loaded: true, Name: "corp.ovpn"}
	if name, err := os.ReadFile(p.ovpnNameFile()); err == nil {
		info.Name = strings.TrimSpace(string(name))
	}
	cfg, err := ovpn.ParseFile(p.ovpnFile())
	if err != nil {
		info.Error = err.Error()
		return info
	}
	r := cfg.Remotes[0]
	port, proto := r.Port, r.Proto
	if port == 0 {
		port = cfg.Port
	}
	if proto == "" {
		proto = cfg.Proto
	}
	info.Server = fmt.Sprintf("%s:%d · %s", r.Host, port, proto)
	info.NeedsAuth = cfg.AuthUserPass && cfg.Username == ""
	return info
}

// inlineOVPN заменяет ссылки на файлы ключей их содержимым, чтобы
// сохранённая копия .ovpn была самодостаточной.
func inlineOVPN(data []byte, cfg *ovpn.Config) []byte {
	blocks := map[string]string{
		"ca": cfg.CA, "cert": cfg.Cert, "key": cfg.Key,
		"tls-auth": cfg.TLSAuth, "tls-crypt": cfg.TLSCrypt, "tls-crypt-v2": cfg.TLSCryptV2,
	}
	var out strings.Builder
	inBlock := false
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		switch {
		case inBlock:
			if strings.HasPrefix(trimmed, "</") {
				inBlock = false
			}
		case strings.HasPrefix(trimmed, "<") && !strings.HasPrefix(trimmed, "</"):
			inBlock = true
		case len(fields) >= 2 && blocks[fields[0]] != "" && fields[1] != "[inline]":
			name := fields[0]
			if name == "tls-auth" && len(fields) > 2 {
				fmt.Fprintf(&out, "key-direction %s\n", fields[2])
			}
			fmt.Fprintf(&out, "<%s>\n%s\n</%s>\n", name, strings.TrimRight(blocks[name], "\n"), name)
			continue
		case len(fields) >= 2 && fields[0] == "auth-user-pass":
			// Логин и пароль из файла переносим в сам конфиг.
			if cfg.Username != "" {
				fmt.Fprintf(&out, "<auth-user-pass>\n%s\n%s\n</auth-user-pass>\n", cfg.Username, cfg.Password)
				continue
			}
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return []byte(out.String())
}
