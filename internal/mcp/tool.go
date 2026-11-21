package mcp

import (
	"context"
	"encoding/json"
	"errors"
)

type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Run         func(ctx context.Context, args json.RawMessage) (string, error)
}

// ErrInvalidParams marks a tool call whose arguments were rejected before anything ran.
// The server reports it as a JSON-RPC invalid-params error; any other Run error becomes a tool result with isError set.
var ErrInvalidParams = errors.New("invalid params")
