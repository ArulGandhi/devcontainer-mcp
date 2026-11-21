package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"
)

const (
	ProtocolVersion = "2025-06-18"
	serverName      = "devcontainer-mcp"
	serverVersion   = "0.1.0"
	instructions    = "Tools act on one preconfigured podman container. exec runs a command with sh -c inside it. read_file and write_file take absolute paths inside it."
)

var supportedVersions = []string{ProtocolVersion, "2025-11-25", "2025-03-26"}

const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  *string         `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type Server struct {
	tools  []Tool
	byName map[string]Tool
	log    *slog.Logger
	slots  chan struct{}
}

func NewServer(tools []Tool, log *slog.Logger, maxConcurrent int) (*Server, error) {
	if log == nil {
		return nil, errors.New("logger is nil")
	}
	if maxConcurrent <= 0 {
		return nil, errors.New("max concurrency must be positive")
	}
	byName := make(map[string]Tool, len(tools))
	for _, t := range tools {
		if t.Name == "" || t.Run == nil {
			return nil, errors.New("tool needs a name and a Run function")
		}
		if _, dup := byName[t.Name]; dup {
			return nil, fmt.Errorf("duplicate tool %q", t.Name)
		}
		byName[t.Name] = t
	}
	return &Server{tools: tools, byName: byName, log: log, slots: make(chan struct{}, maxConcurrent)}, nil
}

// Handle answers one JSON-RPC message. It returns nil when the message needs no reply (notifications and client responses).
func (s *Server) Handle(ctx context.Context, raw []byte) *response {
	if bytes.HasPrefix(bytes.TrimLeft(raw, " \t\r\n"), []byte("[")) {
		return rpcError(nil, codeInvalidRequest, "batch requests are not supported by protocol "+ProtocolVersion)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return rpcError(nil, codeParseError, "parse error: "+err.Error())
	}
	if env.Method == nil {
		if env.Result != nil || env.Error != nil {
			return nil
		}
		return rpcError(env.ID, codeInvalidRequest, "message has no method")
	}
	if env.JSONRPC != "2.0" {
		return rpcError(env.ID, codeInvalidRequest, `jsonrpc must be "2.0"`)
	}
	if len(env.ID) == 0 {
		return nil
	}
	switch *env.Method {
	case "initialize":
		return s.initialize(env.ID, env.Params)
	case "ping":
		return result(env.ID, map[string]any{})
	case "tools/list":
		return result(env.ID, map[string]any{"tools": s.toolDefs()})
	case "tools/call":
		return s.callTool(ctx, env.ID, env.Params)
	default:
		return rpcError(env.ID, codeMethodNotFound, "method not found: "+*env.Method)
	}
}

type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
}

func (s *Server) initialize(id, params json.RawMessage) *response {
	var p initializeParams
	if err := decodeParams(params, &p); err != nil {
		return rpcError(id, codeInvalidParams, err.Error())
	}
	version := ProtocolVersion
	if slices.Contains(supportedVersions, p.ProtocolVersion) {
		version = p.ProtocolVersion
	}
	return result(id, map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": serverName, "version": serverVersion},
		"instructions":    instructions,
	})
}

func (s *Server) toolDefs() []map[string]any {
	defs := make([]map[string]any, 0, len(s.tools))
	for _, t := range s.tools {
		defs = append(defs, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		})
	}
	return defs
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func (s *Server) callTool(ctx context.Context, id, params json.RawMessage) *response {
	var p callParams
	if err := decodeParams(params, &p); err != nil {
		return rpcError(id, codeInvalidParams, err.Error())
	}
	tool, ok := s.byName[p.Name]
	if !ok {
		return rpcError(id, codeInvalidParams, fmt.Sprintf("unknown tool %q", p.Name))
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return toolResult(id, "server busy: too many tool calls are running, retry shortly", true)
	}
	start := time.Now()
	text, err := tool.Run(ctx, p.Arguments)
	if errors.Is(err, ErrInvalidParams) {
		return rpcError(id, codeInvalidParams, err.Error())
	}
	isErr := err != nil
	if isErr {
		text = err.Error()
	}
	s.log.Info("tool call", "tool", p.Name, "duration_ms", time.Since(start).Milliseconds(), "is_error", isErr)
	return toolResult(id, text, isErr)
}

func decodeParams(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return errors.New("params are required")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("invalid params: %v", err)
	}
	return nil
}

func toolResult(id json.RawMessage, text string, isErr bool) *response {
	return result(id, map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isErr,
	})
}

func result(id json.RawMessage, v any) *response {
	return &response{JSONRPC: "2.0", ID: id, Result: v}
}

func rpcError(id json.RawMessage, code int, msg string) *response {
	return &response{JSONRPC: "2.0", ID: id, Error: &RPCError{Code: code, Message: msg}}
}
