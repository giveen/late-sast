package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"late/internal/client"
	"late/internal/common"
)

// TUIInputProvider implements common.InputProvider by sending messages to the TUI.
type TUIInputProvider struct {
	Messenger Messenger
}

func NewTUIInputProvider(messenger Messenger) *TUIInputProvider {
	return &TUIInputProvider{Messenger: messenger}
}

func (p *TUIInputProvider) Prompt(ctx context.Context, req common.PromptRequest) (json.RawMessage, error) {
	if p.Messenger == nil {
		return nil, fmt.Errorf("tui input provider: no messenger available")
	}

	resultCh := make(chan json.RawMessage, 1)
	errCh := make(chan error, 1)

	p.Messenger.Send(PromptRequestMsg{
		OrchestratorID: common.GetOrchestratorID(ctx),
		Request:        req,
		ResultCh:       resultCh,
		ErrCh:          errCh,
	})

	select {
	case result := <-resultCh:
		return result, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// PromptRequestMsg is sent to the TUI to request user input.
type PromptRequestMsg struct {
	OrchestratorID string
	Request        common.PromptRequest
	ResultCh       chan json.RawMessage
	ErrCh          chan error
}

// TUIConfirmMiddleware implements tool confirmation using the TUI.
func TUIConfirmMiddleware(messenger Messenger, reg *common.ToolRegistry) common.ToolMiddleware {
	return func(next common.ToolRunner) common.ToolRunner {
		return func(ctx context.Context, tc client.ToolCall) (string, error) {
			if messenger == nil {
				return next(ctx, tc)
			}

			// Skip confirmation if the tool doesn't require it
			if reg != nil {
				if t := reg.Get(tc.Function.Name); t != nil {
					if !t.RequiresConfirmation(json.RawMessage(tc.Function.Arguments)) {
						return next(ctx, tc)
					}
				}
			}

			// For now, we assume all tools needing confirmation are handled here.
			// The executor handles checking RequiresConfirmation before calling the runner,
			// BUT if we want to confirm HERE, we need to know if it's required.
			// Actually, ExecuteToolCalls in executor.go just runs the runner.
			// So we should check RequiresConfirmation here if we want to intercept.

			// For simplicity in this PR, let's assume the Orchestrator provides
			// the middleware only if it wants confirmation.

			resultCh := make(chan bool, 1)
			errCh := make(chan error, 1)

			messenger.Send(ConfirmRequestMsg{
				OrchestratorID: common.GetOrchestratorID(ctx),
				ToolCall:       tc,
				ResultCh:       resultCh,
				ErrCh:          errCh,
			})

			select {
			case confirmed := <-resultCh:
				if !confirmed {
					return "Tool execution cancelled by user", nil
				}
				return next(ctx, tc)
			case err := <-errCh:
				return "", err
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
	}
}

// ConfirmRequestMsg is sent to the TUI to request tool execution confirmation.
type ConfirmRequestMsg struct {
	OrchestratorID string
	ToolCall       client.ToolCall
	ResultCh       chan bool
	ErrCh          chan error
}
