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

	// Acquire the lock.
	if err := coord.AcquireGPULock(context.Background()); err != nil {
		t.Fatalf("setup acquire failed: %v", err)
	}

	// Release the lock asynchronously after a short delay.
	go func() {
		time.Sleep(30 * time.Millisecond)
		coord.ReleaseGPULock()
	}()

	// Second acquire should block briefly then succeed.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := coord.AcquireGPULock(ctx); err != nil {
		t.Fatalf("expected acquire to succeed after release, got: %v", err)
	}
	coord.ReleaseGPULock()
}

func TestGlobalGPU_NotNil(t *testing.T) {
	if GlobalGPU == nil {
		t.Fatal("GlobalGPU should not be nil")
	}
}
