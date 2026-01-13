//go:build ignore

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"
	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/gen/deputy/sandbox/v1/sandboxv1connect"
)

func main() {
	socketPath := "/tmp/test-vz.sock"

	// Create HTTP client that connects over Unix socket
	client := sandboxv1connect.NewSandboxRuntimeServiceClient(
		&http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
		},
		"http://localhost",
	)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Execute command
	command := []string{"echo", "hello world from VM"}
	if len(os.Args) > 1 {
		command = os.Args[1:]
	}

	req := &sandboxv1.RuntimeExecuteRequest{
		ExecutionId:  "test-exec-1",
		WorkspaceDir: "/tmp",
		Command:      command,
	}

	fmt.Printf("Executing command: %v\n", command)
	stream, err := client.Execute(ctx, connect.NewRequest(req))
	if err != nil {
		log.Fatalf("Execute failed: %v", err)
	}

	for stream.Receive() {
		event := stream.Msg()
		switch e := event.Details.(type) {
		case *sandboxv1.ExecuteEvent_Started:
			fmt.Printf("Started: execution_id=%s\n", e.Started.GetExecutionId())
		case *sandboxv1.ExecuteEvent_Output:
			streamType := "stdout"
			if e.Output.GetIsStderr() {
				streamType = "stderr"
			}
			fmt.Printf("Output (%s): %s", streamType, string(e.Output.GetData()))
		case *sandboxv1.ExecuteEvent_Completed:
			fmt.Printf("Completed: exit_code=%d\n", e.Completed.GetExitCode())
		case *sandboxv1.ExecuteEvent_Error:
			fmt.Printf("Error: code=%s message=%s\n", e.Error.GetCode(), e.Error.GetMessage())
		}
	}

	if err := stream.Err(); err != nil {
		log.Fatalf("Stream error: %v", err)
	}
}
