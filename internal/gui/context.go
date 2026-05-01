package gui

import (
	"context"
	"late/internal/common"
)

// newContextWithProvider returns a new Background context carrying the given provider.
func newContextWithProvider(p common.InputProvider) context.Context {
	return context.WithValue(context.Background(), common.InputProviderKey, p)
}

// withProvider attaches a provider to an existing context.
func withProvider(ctx context.Context, p common.InputProvider) context.Context {
	return context.WithValue(ctx, common.InputProviderKey, p)
}
