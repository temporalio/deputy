package lsp

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	protocol "github.com/sourcegraph/go-lsp"
	"github.com/sourcegraph/jsonrpc2"
)

// TestLSPDiagnosticsAndCodeActionsEndToEnd simulates a client talking to the LSP
// over an in-memory net.Pipe to ensure initialize -> didOpen -> diagnostics -> codeAction flow works.
func TestLSPDiagnosticsAndCodeActionsEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	serverSide, clientSide := net.Pipe()

	// Server handler
	h := newHandler(nil)
	serverConn := jsonrpc2.NewConn(ctx, jsonrpc2.NewBufferedStream(serverSide, jsonrpc2.VSCodeObjectCodec{}), h)
	h.setConn(serverConn)

	// Client-side handler to capture diagnostics notifications
	diagCh := make(chan protocol.PublishDiagnosticsParams, 1)
	clientHandler := jsonrpc2.HandlerWithError(func(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) (any, error) {
		if req.Notif && req.Method == "textDocument/publishDiagnostics" {
			var p protocol.PublishDiagnosticsParams
			_ = json.Unmarshal(*req.Params, &p)
			select {
			case diagCh <- p:
			default:
			}
			return nil, nil
		}
		return nil, nil
	})
	clientConn := jsonrpc2.NewConn(ctx, jsonrpc2.NewBufferedStream(clientSide, jsonrpc2.VSCodeObjectCodec{}), clientHandler)

	// Initialize
	var initResult protocol.InitializeResult
	if err := clientConn.Call(ctx, "initialize", protocol.InitializeParams{}, &initResult); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	// Open a document with a missing reason to trigger diagnostics/code action
	docText := "policies:\n  - name: p\n    rules:\n      - action: deny\n        when: true\n"
	didOpen := protocol.DidOpenTextDocumentParams{TextDocument: protocol.TextDocumentItem{URI: "file:///buf.yaml", LanguageID: "yaml", Version: 1, Text: docText}}
	if err := clientConn.Notify(ctx, "textDocument/didOpen", didOpen); err != nil {
		t.Fatalf("didOpen: %v", err)
	}

	var diag protocol.PublishDiagnosticsParams
	select {
	case diag = <-diagCh:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for diagnostics")
	}
	if len(diag.Diagnostics) == 0 {
		t.Fatalf("expected diagnostics")
	}

	params := protocol.CodeActionParams{TextDocument: protocol.TextDocumentIdentifier{URI: "file:///buf.yaml"}, Context: protocol.CodeActionContext{Diagnostics: diag.Diagnostics}}
	var actions []any
	if err := clientConn.Call(ctx, "textDocument/codeAction", params, &actions); err != nil {
		t.Fatalf("codeAction: %v", err)
	}
	if len(actions) == 0 {
		t.Fatalf("expected at least one code action")
	}

	clientConn.Close()
	serverConn.Close()
}
