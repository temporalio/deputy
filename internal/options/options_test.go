package options

import (
	"errors"
	"testing"
)

type validOptions struct{}

func (validOptions) Validate() error { return nil }

type invalidOptions struct {
	err error
}

func (o invalidOptions) Validate() error { return o.err }

type nonValidatingOptions struct{}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name:    "nil input",
			input:   nil,
			wantErr: false,
		},
		{
			name:    "valid options",
			input:   validOptions{},
			wantErr: false,
		},
		{
			name:    "invalid options",
			input:   invalidOptions{err: errors.New("invalid")},
			wantErr: true,
		},
		{
			name:    "non-validating options",
			input:   nonValidatingOptions{},
			wantErr: false,
		},
		{
			name:    "pointer to valid options",
			input:   &validOptions{},
			wantErr: false,
		},
		{
			name:    "pointer to invalid options",
			input:   &invalidOptions{err: errors.New("invalid")},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMustValidate(t *testing.T) {
	t.Parallel()

	t.Run("valid options", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("MustValidate() panicked unexpectedly: %v", r)
			}
		}()
		MustValidate(validOptions{})
	})

	t.Run("invalid options panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("MustValidate() did not panic for invalid options")
			}
		}()
		MustValidate(invalidOptions{err: errors.New("invalid")})
	})
}
