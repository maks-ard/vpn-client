package app

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// OVPNCandidate не содержит содержимого профиля или ключей.
type OVPNCandidate struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// FindOVPN ищет только в известных каталогах, не читая сами конфигурации.
func FindOVPN(roots []string) []OVPNCandidate {
	result := []OVPNCandidate{}
	seen := map[string]bool{}
	var scan func(string, int)
	scan = func(root string, depth int) {
		entries, err := os.ReadDir(root)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			path := filepath.Join(root, entry.Name())
			if entry.IsDir() {
				if depth > 0 {
					scan(path, depth-1)
				}
				continue
			}
			ext := strings.ToLower(filepath.Ext(path))
			key := strings.ToLower(filepath.Clean(path))
			if (ext == ".ovpn" || ext == ".conf") && !seen[key] {
				seen[key] = true
				result = append(result, OVPNCandidate{Name: entry.Name(), Path: path})
			}
		}
	}
	for _, root := range roots {
		if root != "" {
			scan(root, 1)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result
}
