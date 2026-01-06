package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestExtractScanFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		wantFlag string
		wantVal  any
	}{
		{
			name:     "output flag",
			args:     []string{"--output", "result.json"},
			wantFlag: "OutPath",
			wantVal:  "result.json",
		},
		{
			name:     "format flag",
			args:     []string{"--format", "json"},
			wantFlag: "Format",
			wantVal:  "json",
		},
		{
			name:     "ignore-unfixed flag",
			args:     []string{"--ignore-unfixed"},
			wantFlag: "IgnoreUnfixed",
			wantVal:  true,
		},
		{
			name:     "show-symbols flag",
			args:     []string{"--show-symbols"},
			wantFlag: "ShowSymbols",
			wantVal:  true,
		},
		{
			name:     "ref flag",
			args:     []string{"--ref", "v1.0.0"},
			wantFlag: "Ref",
			wantVal:  "v1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "test"}
			// Register all the flags that extractScanFlags expects
			cmd.Flags().String("output", "", "")
			cmd.Flags().String("format", "", "")
			cmd.Flags().Bool("ignore-unfixed", false, "")
			cmd.Flags().String("published-before", "", "")
			cmd.Flags().String("published-after", "", "")
			cmd.Flags().String("as-of", "", "")
			cmd.Flags().StringArray("policy", nil, "")
			cmd.Flags().Bool("show-symbols", false, "")
			cmd.Flags().Bool("show-db-info", false, "")
			cmd.Flags().Bool("show-unfixable-guidance", false, "")
			cmd.Flags().StringSlice("ecosystems", nil, "")
			cmd.Flags().String("ref", "", "")
			cmd.Flags().String("input-format", "", "")
			cmd.Flags().Bool("enrich", false, "")

			if err := cmd.ParseFlags(tt.args); err != nil {
				t.Fatalf("ParseFlags() error = %v", err)
			}

			flags := extractScanFlags(cmd)

			var got any
			switch tt.wantFlag {
			case "OutPath":
				got = flags.OutPath
			case "Format":
				got = flags.Format
			case "IgnoreUnfixed":
				got = flags.IgnoreUnfixed
			case "ShowSymbols":
				got = flags.ShowSymbols
			case "Ref":
				got = flags.Ref
			default:
				t.Fatalf("unknown flag: %s", tt.wantFlag)
			}

			if got != tt.wantVal {
				t.Errorf("extractScanFlags().%s = %v, want %v", tt.wantFlag, got, tt.wantVal)
			}
		})
	}
}

func TestScanFlags_DisplayOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		flags                 scanFlags
		wantSymbols           bool
		wantDBInfo            bool
		wantUnfixableGuidance bool
	}{
		{
			name:                  "all false",
			flags:                 scanFlags{},
			wantSymbols:           false,
			wantDBInfo:            false,
			wantUnfixableGuidance: false,
		},
		{
			name:                  "symbols true",
			flags:                 scanFlags{ShowSymbols: true},
			wantSymbols:           true,
			wantDBInfo:            false,
			wantUnfixableGuidance: false,
		},
		{
			name:                  "db info true",
			flags:                 scanFlags{ShowDBInfo: true},
			wantSymbols:           false,
			wantDBInfo:            true,
			wantUnfixableGuidance: false,
		},
		{
			name:                  "both true",
			flags:                 scanFlags{ShowSymbols: true, ShowDBInfo: true},
			wantSymbols:           true,
			wantDBInfo:            true,
			wantUnfixableGuidance: false,
		},
		{
			name:                  "unfixable guidance true",
			flags:                 scanFlags{ShowUnfixableGuidance: true},
			wantSymbols:           false,
			wantDBInfo:            false,
			wantUnfixableGuidance: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.flags.displayOptions()
			if opts.ShowSymbols != tt.wantSymbols {
				t.Errorf("displayOptions().ShowSymbols = %v, want %v", opts.ShowSymbols, tt.wantSymbols)
			}
			if opts.ShowDatabaseInfo != tt.wantDBInfo {
				t.Errorf("displayOptions().ShowDatabaseInfo = %v, want %v", opts.ShowDatabaseInfo, tt.wantDBInfo)
			}
			if opts.ShowUnfixableGuidance != tt.wantUnfixableGuidance {
				t.Errorf("displayOptions().ShowUnfixableGuidance = %v, want %v", opts.ShowUnfixableGuidance, tt.wantUnfixableGuidance)
			}
		})
	}
}

func TestScanFlags_ScanOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		ecosystems     []string
		wantEcosystems []string
	}{
		{
			name:           "no ecosystems",
			ecosystems:     nil,
			wantEcosystems: nil,
		},
		{
			name:           "single ecosystem",
			ecosystems:     []string{"go"},
			wantEcosystems: []string{"go"},
		},
		{
			name:           "multiple ecosystems",
			ecosystems:     []string{"go", "npm", "pypi"},
			wantEcosystems: []string{"go", "npm", "pypi"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := scanFlags{Ecosystems: tt.ecosystems}
			opts := flags.scanOptions()
			if len(opts.Ecosystems) != len(tt.wantEcosystems) {
				t.Errorf("scanOptions().Ecosystems len = %d, want %d", len(opts.Ecosystems), len(tt.wantEcosystems))
				return
			}
			for i, eco := range opts.Ecosystems {
				if eco != tt.wantEcosystems[i] {
					t.Errorf("scanOptions().Ecosystems[%d] = %s, want %s", i, eco, tt.wantEcosystems[i])
				}
			}
		})
	}
}

func TestOpenOutputWriter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		outPath    string
		wantStdout bool
		wantErr    bool
		writeData  string
		checkFile  bool
	}{
		{
			name:       "empty path uses stdout",
			outPath:    "",
			wantStdout: true,
		},
		{
			name:       "dash uses stdout",
			outPath:    "-",
			wantStdout: true,
		},
		{
			name:      "file path creates file",
			outPath:   "", // will be set to temp file
			checkFile: true,
			writeData: "test output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := &cobra.Command{Use: "test"}
			cmd.SetOut(&buf)

			outPath := tt.outPath
			if tt.checkFile {
				tmpDir := t.TempDir()
				outPath = filepath.Join(tmpDir, "output.txt")
			}

			ow, err := openOutputWriter(cmd, outPath)
			if (err != nil) != tt.wantErr {
				t.Fatalf("openOutputWriter() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			defer ow.Close()

			if tt.wantStdout {
				// Write to the output writer and check it goes to stdout
				_, err := ow.Writer.Write([]byte("test"))
				if err != nil {
					t.Fatalf("Write() error = %v", err)
				}
				if buf.String() != "test" {
					t.Errorf("expected stdout output, got %q", buf.String())
				}
			}

			if tt.checkFile {
				_, err := ow.Writer.Write([]byte(tt.writeData))
				if err != nil {
					t.Fatalf("Write() error = %v", err)
				}
				if err := ow.Close(); err != nil {
					t.Fatalf("Close() error = %v", err)
				}

				content, err := os.ReadFile(outPath)
				if err != nil {
					t.Fatalf("ReadFile() error = %v", err)
				}
				if string(content) != tt.writeData {
					t.Errorf("file content = %q, want %q", string(content), tt.writeData)
				}
			}
		})
	}
}

func TestOutputWriter_Close(t *testing.T) {
	t.Parallel()

	t.Run("nil closer", func(t *testing.T) {
		ow := &outputWriter{Writer: &bytes.Buffer{}}
		if err := ow.Close(); err != nil {
			t.Errorf("Close() error = %v, want nil", err)
		}
	})

	t.Run("with closer", func(t *testing.T) {
		tmpFile, err := os.CreateTemp(t.TempDir(), "test")
		if err != nil {
			t.Fatalf("CreateTemp() error = %v", err)
		}
		ow := &outputWriter{Writer: tmpFile, closer: tmpFile}
		if err := ow.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
		// Second close should error (file already closed)
		if err := tmpFile.Close(); err == nil {
			t.Error("expected error closing already-closed file")
		}
	})
}

func TestFormatConstants(t *testing.T) {
	t.Parallel()

	// Verify format constants have expected values
	tests := []struct {
		name     string
		constant string
		want     string
	}{
		{"FormatText", FormatText, "text"},
		{"FormatJSON", FormatJSON, "json"},
		{"FormatTSV", FormatTSV, "tsv"},
		{"FormatSARIF", FormatSARIF, "sarif"},
		{"FormatCycloneDX", FormatCycloneDX, "cyclonedx"},
		{"FormatCycloneDXJSON", FormatCycloneDXJSON, "cyclonedx-json"},
		{"FormatSPDX", FormatSPDX, "spdx"},
		{"FormatSPDXJSON", FormatSPDXJSON, "spdx-json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.constant, tt.want)
			}
		})
	}
}
