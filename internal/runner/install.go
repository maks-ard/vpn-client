package runner

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Install распаковывает встроенный sing-box в dir и открывает его так, что
// до вызова release файл нельзя подменить: vpnclient работает с правами
// администратора, а папка с программой может быть доступна на запись
// обычному пользователю.
func Install(dir string, data []byte) (path string, release func(), err error) {
	if path, release, err := Open(dir, data); err == nil {
		return path, release, nil
	}
	path = Path(dir)
	name := filepath.Base(path)
	want := sha256.Sum256(data)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	tmp, err := os.CreateTemp(dir, name+".*.tmp")
	if err != nil {
		return "", nil, err
	}
	_, err = io.Copy(tmp, bytes.NewReader(data))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o755)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("распаковка sing-box: %w", err)
	}

	f, err := openLocked(path)
	if err != nil {
		return "", nil, fmt.Errorf("распаковка sing-box: %w", err)
	}
	if sum, err := hashFile(f); err != nil || sum != want {
		_ = f.Close()
		return "", nil, fmt.Errorf("распакованный sing-box повреждён или подменён: %s", path)
	}
	return path, func() { _ = f.Close() }, nil
}

// Path — куда Install распаковывает sing-box.
func Path(dir string) string {
	name := "sing-box"
	if isWindows {
		name += ".exe"
	}
	return filepath.Join(dir, name)
}

// Open открывает уже распакованный sing-box так же, как Install, но ничего не
// записывает: файл работающего процесса заменить нельзя. Ошибка — файла нет
// или он отличается от встроенного.
func Open(dir string, data []byte) (path string, release func(), err error) {
	path = Path(dir)
	f, err := openLocked(path)
	if err != nil {
		return "", nil, err
	}
	sum, err := hashFile(f)
	if err == nil && sum != sha256.Sum256(data) {
		err = fmt.Errorf("%s отличается от встроенного sing-box", path)
	}
	if err != nil {
		_ = f.Close()
		return "", nil, err
	}
	return path, func() { _ = f.Close() }, nil
}

func hashFile(f *os.File) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return sum, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}
