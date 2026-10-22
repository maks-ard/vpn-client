package winsvc

import (
	"errors"

	"github.com/go-ole/go-ole"
)

// S_FALSE — успешная повторная инициализация COM, а не ошибка.
func isCOMInitialized(err error) bool {
	var oleErr *ole.OleError
	return errors.As(err, &oleErr) && oleErr.Code() == 1
}
