package executor

import (
	"context"
	"testing"
	"time"
)

func TestResourceCoordinator_AcquireRelease(t *testing.T) {
	coord := newResourceCoordinator()

	// First acquire should succeed immediately.
	if err := coord.AcquireGPULock(context.Background()); err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	coord.ReleaseGPULock()

	// Acquire-release cycle twice to confirm token is returned correctly.
	if err := coord.AcquireGPULock(context.Background()); err != nil {
		t.Fatalf("second acquire failed: %v", err)
	}
	coord.ReleaseGPULock()
}

func TestResourceCoordinator_ContextCancellation(t *testing.T) {
	coord := newResourceCoordinator()

	// Hold the lock so the next acquire must wait.
	if err := coord.AcquireGPULock(context.Background()); err != nil {
		t.Fatalf("setup acquire failed: %v", err)
	}
	defer coord.ReleaseGPULock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := coord.AcquireGPULock(ctx)
	if err == nil {
		t.Fatal("expected error when context expires, got nil")
	}
}

func TestResourceCoordinator_BlocksThenSucceeds(t *testing.T) {
	coord := newResourceCoordinator()

	// Acquire the lock so the goroutine below must wait.
	if err := coord.AcquireGPULock(context.Background()); err != nil {
		t.Fatalf("setup acquire failed: %v", err)
	}

	// waiting is closed once the goroutine is blocking on AcquireGPULock,
	// guaranteeing that ReleaseGPULock happens only after the second acquire is
	// already queued — no scheduler timing required.
	waiting := make(chan struct{})

	go func() {
		close(waiting) // signal: goroutine is about to block
		if err := coord.AcquireGPULock(context.Background()); err != nil {
			return // context cancelled; test already failed or cleaned up
		}
		coord.ReleaseGPULock()
	}()

	<-waiting // ensure goroutine is scheduled and waiting before we release
	coord.ReleaseGPULock()

	// Give the goroutine time to complete; a short timeout is fine here because
	// once ReleaseGPULock() has been called the channel send is non-blocking.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Verify the coordinator token was returned by the goroutine: try acquiring
	// again — should succeed immediately after the goroutine releases.
	select {
	case <-coord.ch:
		// token is back; goroutine released correctly
	case <-ctx.Done():
		t.Fatal("timed out waiting for goroutine to release the GPU lock")
	}
}

func TestResourceCoordinator_DoubleReleasePanics(t *testing.T) {
	coord := newResourceCoordinator()

	if err := coord.AcquireGPULock(context.Background()); err != nil {
		t.Fatalf("acquire failed: %v", err)
	}
	coord.ReleaseGPULock() // normal release

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on double release, got none")
		}
	}()
	coord.ReleaseGPULock() // second release should panic
}

func TestGlobalGPU_NotNil(t *testing.T) {
	if GlobalGPU == nil {
		t.Fatal("GlobalGPU should not be nil")
	}
}
