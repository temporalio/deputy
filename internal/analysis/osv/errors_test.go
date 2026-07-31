package osv

import (
	"errors"
	"testing"
)

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
		},
		{
			name: "osv 404",
			err:  errors.New(`client error: status="404 Not Found" body={"code":5,"message":"Bug not found."}`),
			want: true,
		},
		{
			name: "grpc code 5 not found body",
			err:  errors.New(`client error: status="400 Bad Request" body={"code":5,"message":"Bug not found."}`),
			want: true,
		},
		{
			name: "invalid query",
			err:  errors.New(`client error: status="400 Bad Request" body={"code":3,"message":"Invalid query."}`),
		},
		{
			name: "network error mentioning not found",
			err:  errors.New("lookup osv.dev: no such host; cache file not found"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFoundError(tt.err); got != tt.want {
				t.Fatalf("IsNotFoundError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
