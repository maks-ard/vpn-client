package winsvc

import (
	"context"
	"fmt"
	"time"
)

// RUNNING недостаточно: окно должно иметь возможность связаться со службой.
func awaitServiceReady(ctx context.Context, probe func() (bool, error)) error {
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("ожидание готовности службы и API: %w", err)
		}
		ready, err := probe()
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}
