//go:build !embed_singbox

// Package singboxbin отдаёт встроенный в релизную сборку sing-box.exe.
// Обычная сборка ничего не встраивает и использует sing-box.exe рядом с программой.
package singboxbin

func Data() []byte { return nil }
