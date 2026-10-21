//go:build embed_singbox

package singboxbin

import _ "embed"

// sing-box.exe кладётся сюда перед релизной сборкой (см. release.yml).
//
//go:embed sing-box.exe
var data []byte

func Data() []byte { return data }
