package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/maks-ard/vpn-client/internal/corproute"
	"github.com/maks-ard/vpn-client/internal/singbox"
)

// Адаптер OpenVPN в Windows (Settings.CorpAdapter). Маршрутов, присланных
// сервером OpenVPN, sing-box наружу не отдаёт, поэтому адреса компании
// служба узнаёт по соединениям, которые sing-box отправил в OpenVPN, и
// прокладывает к ним маршруты через адаптер. Тогда программы, например
// агент Kaspersky, выходят к этим адресам с адреса из пула OpenVPN, и
// сервер компании видит компьютер по нему, как с обычным клиентом.
// Адреса запоминаются: при следующем подключении маршруты появляются
// сразу, до первого соединения программы.

const (
	// maxCorpHosts ограничивает список: маршруты нужны к серверам компании,
	// а не ко всему, что там открывалось.
	maxCorpHosts       = 256
	corpRoutesInterval = 3 * time.Second
	// Пока адаптера нет, проверяем чаще: до маршрута по умолчанию через
	// него sing-box не может открыть ни одного корпоративного соединения.
	corpAdapterWait = time.Second
)

func (p Paths) corpHostsFile() string { return filepath.Join(p.Data, "corp-hosts.json") }

func loadCorpHosts(p Paths) []netip.Addr {
	data, err := os.ReadFile(p.corpHostsFile())
	if err != nil {
		return nil
	}
	var hosts []netip.Addr
	if json.Unmarshal(data, &hosts) != nil {
		return nil
	}
	return hosts
}

func saveCorpHosts(p Paths, hosts []netip.Addr) error {
	data, err := json.Marshal(hosts)
	if err != nil {
		return err
	}
	return writeFileAtomic(p.corpHostsFile(), data)
}

// learnCorpHosts добавляет к hosts адреса соединений, которые sing-box
// отправил в OpenVPN. Берутся только частные IPv4: публичный адрес может
// принадлежать и сайтам вне компании, и маршрут увёл бы их в OpenVPN.
// При переполнении забываются самые старые адреса.
func learnCorpHosts(hosts []netip.Addr, conns []clashConnection) ([]netip.Addr, bool) {
	changed := false
	for _, c := range conns {
		if !slices.Contains(c.Chains, singbox.TagCorp) {
			continue
		}
		addr, err := netip.ParseAddr(c.Metadata.DestinationIP)
		if err != nil || !addr.Is4() || !addr.IsPrivate() || slices.Contains(hosts, addr) {
			continue
		}
		hosts = append(hosts, addr)
		changed = true
	}
	if len(hosts) > maxCorpHosts {
		hosts = slices.Clone(hosts[len(hosts)-maxCorpHosts:])
	}
	return hosts, changed
}

// corpRoutes держит маршруты через адаптер OpenVPN, пока идёт сессия.
// Адаптер появляется, когда OpenVPN подключился, и пересоздаётся при
// переподключении с другим адресом, поэтому маршруты проверяются по кругу.
func (m *Manager) corpRoutes(ctx context.Context, api *clash) {
	hosts := loadCorpHosts(m.paths)
	lastErr := ""
	for ctx.Err() == nil {
		wait := corpRoutesInterval
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conns, err := api.connections(reqCtx)
		cancel()
		if err == nil {
			var changed bool
			if hosts, changed = learnCorpHosts(hosts, conns); changed {
				if err := saveCorpHosts(m.paths, hosts); err != nil {
					m.log.Printf("адаптер OpenVPN: не удалось сохранить адреса компании: %v", err)
				}
			}
		}
		added, err := m.ensureRoutes(singbox.CorpInterfaceName, hosts)
		switch {
		case err == nil:
			if added > 0 {
				m.log.Printf("адаптер OpenVPN: добавлено маршрутов: %d (адресов компании: %d)", added, len(hosts))
			}
			lastErr = ""
		case errors.Is(err, corproute.ErrNoAdapter):
			// OpenVPN ещё подключается.
			wait = corpAdapterWait
		case err.Error() != lastErr:
			m.log.Printf("адаптер OpenVPN: %v", err)
			lastErr = err.Error()
		}
		sleep(ctx, wait)
	}
}
