package winsvc

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAwaitServiceReady(t *testing.T) {
	t.Run("ожидание API", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		calls := 0
		err := awaitServiceReady(ctx, func() (bool, error) {
			calls++
			return calls == 2, nil
		})
		if err != nil || calls != 2 {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	})
	t.Run("ошибка запуска", func(t *testing.T) {
		want := errors.New("служба остановилась")
		if err := awaitServiceReady(context.Background(), func() (bool, error) { return false, want }); !errors.Is(err, want) {
			t.Fatal(err)
		}
	})
	t.Run("таймаут", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if err := awaitServiceReady(ctx, func() (bool, error) { return false, nil }); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	})
}
