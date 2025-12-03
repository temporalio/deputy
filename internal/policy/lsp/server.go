package lsp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"

	protocol "github.com/sourcegraph/go-lsp"
	"github.com/sourcegraph/jsonrpc2"
)

// Options configure the LSP server.
type Options struct {
	UseStdio bool
	TCP      string // optional "127.0.0.1:0" style
	Log      *slog.Logger
}

// Run starts the LSP server and blocks until the connection ends.
func Run(ctx context.Context, opts Options) error {
	log := opts.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	handler := newHandler(log)

	serveConn := func(rwc io.ReadWriteCloser) error {
		stream := jsonrpc2.NewBufferedStream(rwc, jsonrpc2.VSCodeObjectCodec{})
		conn := jsonrpc2.NewConn(ctx, stream, handler)
		handler.setConn(conn)
		<-conn.DisconnectNotify()
		return nil
	}

	if !opts.UseStdio && opts.TCP != "" {
		ln, err := net.Listen("tcp", opts.TCP)
		if err != nil {
			return err
		}
		log.Info("deputy policy lsp listening", "addr", ln.Addr().String())
		defer ln.Close()
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return err
			}
			go func() {
				defer c.Close()
				if err := serveConn(c); err != nil {
					log.Error("lsp connection ended", "err", err)
				}
			}()
		}
	}

	// stdio
	return serveConn(struct {
		io.Reader
		io.Writer
		io.Closer
	}{Reader: os.Stdin, Writer: os.Stdout, Closer: io.NopCloser(nil)})
}

// handler implements jsonrpc2.Handler.
type handler struct {
	conn *jsonrpc2.Conn
	log  *slog.Logger
	docs *documentStore
	diag *diagnosticEngine
}

func newHandler(log *slog.Logger) *handler {
	return &handler{
		log:  log,
		docs: newDocumentStore(),
		diag: newDiagnosticEngine(),
	}
}

func (h *handler) setConn(c *jsonrpc2.Conn) { h.conn = c }

func (h *handler) Handle(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {
	switch req.Method {
	case "initialize":
		var params protocol.InitializeParams
		if req.Params != nil {
			_ = json.Unmarshal(*req.Params, &params)
		}
		kind := protocol.TDSKFull
		res := initializeResultWithServerInfo{
			InitializeResult: protocol.InitializeResult{
				Capabilities: protocol.ServerCapabilities{
					TextDocumentSync: &protocol.TextDocumentSyncOptionsOrKind{Kind: &kind},
					CompletionProvider: &protocol.CompletionOptions{
						ResolveProvider: false,
					},
					HoverProvider:          true,
					DocumentSymbolProvider: true,
					CodeActionProvider:     true,
				},
			},
			ServerInfo: serverInfo{Name: "deputy-policy-lsp", Version: "0.1.0"},
		}
		_ = conn.Reply(ctx, req.ID, res)
	case "shutdown":
		_ = conn.Reply(ctx, req.ID, nil)
	case "textDocument/didOpen":
		var params protocol.DidOpenTextDocumentParams
		if req.Params != nil {
			_ = json.Unmarshal(*req.Params, &params)
		}
		doc := params.TextDocument
		h.docs.open(doc.URI, doc.Text, doc.Version)
		h.runDiagnostics(ctx, doc.URI, doc.Text)
	case "textDocument/didChange":
		var params protocol.DidChangeTextDocumentParams
		if req.Params != nil {
			_ = json.Unmarshal(*req.Params, &params)
		}
		if len(params.ContentChanges) == 0 {
			return
		}
		text := params.ContentChanges[len(params.ContentChanges)-1].Text
		if _, ok := h.docs.update(params.TextDocument.URI, text, params.TextDocument.Version); ok {
			h.runDiagnostics(ctx, params.TextDocument.URI, text)
		}
	case "textDocument/completion":
		var params protocol.CompletionParams
		if req.Params != nil {
			_ = json.Unmarshal(*req.Params, &params)
		}
		items := h.handleCompletion(params)
		_ = conn.Reply(ctx, req.ID, protocol.CompletionList{IsIncomplete: false, Items: items})
	case "textDocument/hover":
		var params protocol.TextDocumentPositionParams
		if req.Params != nil {
			_ = json.Unmarshal(*req.Params, &params)
		}
		hover := h.handleHover(params)
		_ = conn.Reply(ctx, req.ID, hover)
	case "textDocument/documentSymbol":
		var params protocol.DocumentSymbolParams
		if req.Params != nil {
			_ = json.Unmarshal(*req.Params, &params)
		}
		syms := h.handleDocumentSymbols(params)
		_ = conn.Reply(ctx, req.ID, syms)
	case "textDocument/codeAction":
		var params protocol.CodeActionParams
		if req.Params != nil {
			_ = json.Unmarshal(*req.Params, &params)
		}
		docText := ""
		if doc, ok := h.docs.get(params.TextDocument.URI); ok {
			if txt, _ := doc.get(); txt != "" {
				docText = txt
			}
		}
		actions := buildCodeActions(params, docText)
		_ = conn.Reply(ctx, req.ID, actions)
	default:
		// Notifications we don't handle explicitly.
		if req.Notif {
			return
		}
		_ = conn.ReplyWithError(ctx, req.ID, &jsonrpc2.Error{Code: jsonrpc2.CodeMethodNotFound, Message: "method not supported"})
	}
}

func (h *handler) runDiagnostics(ctx context.Context, uri protocol.DocumentURI, text string) {
	diag, err := h.diag.analyze(uri, text)
	if err != nil {
		h.log.Warn("diagnostics failed", "err", err)
		return
	}
	params := protocol.PublishDiagnosticsParams{
		URI:         uri,
		Diagnostics: diag,
	}
	if h.conn != nil {
		_ = h.conn.Notify(ctx, "textDocument/publishDiagnostics", params)
	}
}

func (h *handler) handleCompletion(params protocol.CompletionParams) []protocol.CompletionItem {
	doc, ok := h.docs.get(params.TextDocument.URI)
	if !ok {
		return nil
	}
	text, _ := doc.get()
	lines := strings.Split(text, "\n")
	if int(params.Position.Line) >= len(lines) {
		return nil
	}
	line := lines[params.Position.Line]
	return completionItems(line, int(params.Position.Character))
}

func (h *handler) handleHover(params protocol.TextDocumentPositionParams) *protocol.Hover {
	doc, ok := h.docs.get(params.TextDocument.URI)
	if !ok {
		return nil
	}
	text, _ := doc.get()
	lines := strings.Split(text, "\n")
	if int(params.Position.Line) >= len(lines) {
		return nil
	}
	line := strings.TrimSpace(lines[params.Position.Line])
	msg := hoverForLine(line)
	if msg == "" {
		return nil
	}
	return &protocol.Hover{
		Contents: []protocol.MarkedString{{Language: "markdown", Value: msg}},
	}
}

func (h *handler) handleDocumentSymbols(params protocol.DocumentSymbolParams) []protocol.SymbolInformation {
	doc, ok := h.docs.get(params.TextDocument.URI)
	if !ok {
		return nil
	}
	text, _ := doc.get()
	syms, err := parseDocumentSymbols(text, params.TextDocument.URI)
	if err != nil {
		h.log.Debug("document symbols parse failed", "err", err)
		return nil
	}
	return syms
}
