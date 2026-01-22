package vmimage

import (
	"testing"
)

func TestPartitionTypeConstants(t *testing.T) {
	// Verify partition type constants are defined correctly
	types := []PartitionType{
		PartitionTypeLinux,
		PartitionTypeLinuxLVM,
		PartitionTypeEFI,
		PartitionTypeSwap,
		PartitionTypeFAT32,
		PartitionTypeNTFS,
		PartitionTypeUnknown,
	}

	for _, pt := range types {
		if pt == "" {
			t.Error("Found empty partition type constant")
		}
	}
}

func TestGptTypeToPartitionType(t *testing.T) {
	tests := []struct {
		guid     string
		expected PartitionType
	}{
		{gptTypeLinuxFilesystem, PartitionTypeLinux},
		{gptTypeLinuxRoot, PartitionTypeLinux},
		{gptTypeLinuxRootARM64, PartitionTypeLinux},
		{gptTypeLinuxLVM, PartitionTypeLinuxLVM},
		{gptTypeEFI, PartitionTypeEFI},
		{gptTypeLinuxSwap, PartitionTypeSwap},
		{gptTypeMSBasic, PartitionTypeNTFS},
		{"UNKNOWN-GUID-0000-0000-000000000000", PartitionTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.guid, func(t *testing.T) {
			got := gptTypeToPartitionType(tt.guid)
			if got != tt.expected {
				t.Errorf("gptTypeToPartitionType(%q) = %q, want %q", tt.guid, got, tt.expected)
			}
		})
	}
}

func TestMbrTypeToPartitionType(t *testing.T) {
	tests := []struct {
		code     byte
		expected PartitionType
	}{
		{mbrTypeLinux, PartitionTypeLinux},
		{mbrTypeLinuxLVM, PartitionTypeLinuxLVM},
		{mbrTypeLinuxSwap, PartitionTypeSwap},
		{mbrTypeEFI, PartitionTypeEFI},
		{mbrTypeFAT32, PartitionTypeFAT32},
		{mbrTypeFAT32LBA, PartitionTypeFAT32},
		{mbrTypeNTFS, PartitionTypeNTFS},
		{0x00, PartitionTypeUnknown},
		{0xFF, PartitionTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.code)), func(t *testing.T) {
			got := mbrTypeToPartitionType(tt.code)
			if got != tt.expected {
				t.Errorf("mbrTypeToPartitionType(0x%02X) = %q, want %q", tt.code, got, tt.expected)
			}
		})
	}
}

func TestFormatGUID(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "valid 16-byte GUID",
			input:    []byte{0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4},
			expected: "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
		},
		{
			name:     "empty slice",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "wrong size",
			input:    []byte{0x01, 0x02, 0x03},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatGUID(tt.input)
			if got != tt.expected {
				t.Errorf("formatGUID(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestClassifyPartitionType(t *testing.T) {
	tests := []struct {
		name      string
		typeBytes []byte
		expected  PartitionType
	}{
		{
			name:      "MBR Linux",
			typeBytes: []byte{mbrTypeLinux},
			expected:  PartitionTypeLinux,
		},
		{
			name:      "MBR EFI",
			typeBytes: []byte{mbrTypeEFI},
			expected:  PartitionTypeEFI,
		},
		{
			name:      "GPT Linux Filesystem",
			typeBytes: []byte{0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4},
			expected:  PartitionTypeLinux,
		},
		{
			name:      "empty",
			typeBytes: []byte{},
			expected:  PartitionTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyPartitionType(tt.typeBytes)
			if got != tt.expected {
				t.Errorf("classifyPartitionType(%v) = %q, want %q", tt.typeBytes, got, tt.expected)
			}
		})
	}
}

func TestPartitionTableFindRootPartition(t *testing.T) {
	tests := []struct {
		name       string
		pt         *PartitionTable
		wantIndex  int
		wantErr    bool
	}{
		{
			name: "single linux partition",
			pt: &PartitionTable{
				Type: "gpt",
				Partitions: []Partition{
					{Index: 1, Size: 1024, Type: PartitionTypeLinux},
				},
			},
			wantIndex: 1,
			wantErr:   false,
		},
		{
			name: "EFI and Linux partitions",
			pt: &PartitionTable{
				Type: "gpt",
				Partitions: []Partition{
					{Index: 1, Size: 512, Type: PartitionTypeEFI},
					{Index: 2, Size: 8192, Type: PartitionTypeLinux},
				},
			},
			wantIndex: 2,
			wantErr:   false,
		},
		{
			name: "multiple Linux partitions returns largest",
			pt: &PartitionTable{
				Type: "gpt",
				Partitions: []Partition{
					{Index: 1, Size: 512, Type: PartitionTypeEFI},
					{Index: 2, Size: 1024, Type: PartitionTypeLinux},
					{Index: 3, Size: 8192, Type: PartitionTypeLinux},
				},
			},
			wantIndex: 3,
			wantErr:   false,
		},
		{
			name: "explicit root type GUID",
			pt: &PartitionTable{
				Type: "gpt",
				Partitions: []Partition{
					{Index: 1, Size: 512, Type: PartitionTypeEFI},
					{Index: 2, Size: 1024, Type: PartitionTypeLinux, TypeGUID: gptTypeLinuxRoot},
					{Index: 3, Size: 8192, Type: PartitionTypeLinux},
				},
			},
			wantIndex: 2, // Returns the one with explicit root GUID, not the largest
			wantErr:   false,
		},
		{
			name: "no Linux partitions",
			pt: &PartitionTable{
				Type: "gpt",
				Partitions: []Partition{
					{Index: 1, Size: 512, Type: PartitionTypeEFI},
					{Index: 2, Size: 8192, Type: PartitionTypeNTFS},
				},
			},
			wantIndex: 0,
			wantErr:   true,
		},
		{
			name: "empty partition table",
			pt: &PartitionTable{
				Type:       "gpt",
				Partitions: []Partition{},
			},
			wantIndex: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.pt.FindRootPartition()
			if tt.wantErr {
				if err == nil {
					t.Errorf("FindRootPartition() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("FindRootPartition() error = %v", err)
			}
			if got.Index != tt.wantIndex {
				t.Errorf("FindRootPartition() returned partition %d, want %d", got.Index, tt.wantIndex)
			}
		})
	}
}

func TestPartitionTableGetPartition(t *testing.T) {
	pt := &PartitionTable{
		Type: "gpt",
		Partitions: []Partition{
			{Index: 1, Size: 512, Type: PartitionTypeEFI},
			{Index: 2, Size: 8192, Type: PartitionTypeLinux},
			{Index: 3, Size: 1024, Type: PartitionTypeSwap},
		},
	}

	tests := []struct {
		index   int
		wantErr bool
	}{
		{index: 1, wantErr: false},
		{index: 2, wantErr: false},
		{index: 3, wantErr: false},
		{index: 0, wantErr: true},
		{index: 4, wantErr: true},
		{index: -1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(string(rune('0'+tt.index)), func(t *testing.T) {
			got, err := pt.GetPartition(tt.index)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetPartition(%d) expected error", tt.index)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetPartition(%d) error = %v", tt.index, err)
			}
			if got.Index != tt.index {
				t.Errorf("GetPartition(%d) returned partition with index %d", tt.index, got.Index)
			}
		})
	}
}

func TestPartitionTableLinuxPartitions(t *testing.T) {
	pt := &PartitionTable{
		Type: "gpt",
		Partitions: []Partition{
			{Index: 1, Size: 512, Type: PartitionTypeEFI},
			{Index: 2, Size: 8192, Type: PartitionTypeLinux},
			{Index: 3, Size: 1024, Type: PartitionTypeSwap},
			{Index: 4, Size: 4096, Type: PartitionTypeLinux},
		},
	}

	linuxParts := pt.LinuxPartitions()
	if len(linuxParts) != 2 {
		t.Fatalf("LinuxPartitions() returned %d partitions, want 2", len(linuxParts))
	}

	indices := []int{linuxParts[0].Index, linuxParts[1].Index}
	if indices[0] != 2 || indices[1] != 4 {
		t.Errorf("LinuxPartitions() returned partitions with indices %v, want [2, 4]", indices)
	}
}
