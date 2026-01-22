package vmimage

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/masahiro331/go-disk"
	"github.com/masahiro331/go-disk/types"
)

// Partition represents a partition within a disk image.
type Partition struct {
	// Index is the partition number (1-based).
	Index int

	// Start is the starting byte offset of the partition.
	Start int64

	// Size is the size of the partition in bytes.
	Size int64

	// Type is the partition type (filesystem type hint).
	Type PartitionType

	// TypeGUID is the GPT partition type GUID (empty for MBR).
	TypeGUID string

	// Name is the partition name (GPT only).
	Name string

	// Bootable indicates if this is a bootable partition.
	Bootable bool
}

// PartitionType represents common partition types.
type PartitionType string

const (
	PartitionTypeLinux    PartitionType = "linux"
	PartitionTypeLinuxLVM PartitionType = "linux_lvm"
	PartitionTypeEFI      PartitionType = "efi"
	PartitionTypeSwap     PartitionType = "swap"
	PartitionTypeFAT32    PartitionType = "fat32"
	PartitionTypeNTFS     PartitionType = "ntfs"
	PartitionTypeUnknown  PartitionType = "unknown"
)

// Common GPT partition type GUIDs.
const (
	gptTypeLinuxFilesystem = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
	gptTypeLinuxRoot       = "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709" // x86-64
	gptTypeLinuxRootARM64  = "B921B045-1DF0-41C3-AF44-4C6F280D3FAE"
	gptTypeLinuxLVM        = "E6D6D379-F507-44C2-A23C-238F2A3DF928"
	gptTypeEFI             = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
	gptTypeLinuxSwap       = "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F"
	gptTypeMSBasic         = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" // NTFS/FAT
)

// Common MBR partition type codes.
const (
	mbrTypeLinux     = 0x83
	mbrTypeLinuxLVM  = 0x8E
	mbrTypeLinuxSwap = 0x82
	mbrTypeEFI       = 0xEF
	mbrTypeFAT32     = 0x0C
	mbrTypeFAT32LBA  = 0x0B
	mbrTypeNTFS      = 0x07
)

// PartitionTable represents a parsed partition table (GPT or MBR).
type PartitionTable struct {
	Type       string // "gpt" or "mbr"
	Partitions []Partition
}

// ErrNoPartitionTable is returned when no partition table is found.
var ErrNoPartitionTable = errors.New("no partition table found")

// ErrNoLinuxPartition is returned when no Linux partition is found.
var ErrNoLinuxPartition = errors.New("no Linux partition found")

// sectorSize is the standard disk sector size.
const sectorSize = 512

// ReadPartitions reads the partition table from a disk image.
// It supports both GPT and MBR partition tables.
func ReadPartitions(d DiskImage) (*PartitionTable, error) {
	// Create an io.SectionReader for the disk
	sr := io.NewSectionReader(d, 0, d.Size())

	// Create the disk driver
	driver, err := disk.NewDriver(sr)
	if err != nil {
		return nil, fmt.Errorf("create disk driver: %w", err)
	}

	pt := &PartitionTable{
		Partitions: make([]Partition, 0),
	}

	// Iterate through partitions using Next()
	index := 1
	for {
		p, err := driver.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("read partition: %w", err)
		}

		if p == nil || !p.IsSupported() {
			continue
		}

		// Get partition information
		// Note: GetStartSector() returns sectors, GetSize() returns sector count
		part := Partition{
			Index:    index,
			Start:    int64(p.GetStartSector()) * sectorSize,
			Size:     int64(p.GetSize()) * sectorSize,
			Name:     p.Name(),
			Bootable: p.Bootable(),
		}

		// Determine partition type from the type bytes
		typeBytes := p.GetType()
		part.Type = classifyPartitionType(typeBytes)

		// If we have a GUID (16 bytes), it's GPT
		if len(typeBytes) == 16 {
			pt.Type = "gpt"
			part.TypeGUID = formatGUID(typeBytes)
		} else if pt.Type == "" {
			pt.Type = "mbr"
		}

		pt.Partitions = append(pt.Partitions, part)
		index++
	}

	if len(pt.Partitions) == 0 {
		return nil, ErrNoPartitionTable
	}

	return pt, nil
}

// FindRootPartition finds the most likely root filesystem partition.
// It uses heuristics to identify the Linux root partition:
// 1. Look for GPT root partition type GUIDs
// 2. Look for Linux filesystem partitions
// 3. Select the largest Linux partition as a fallback
func (pt *PartitionTable) FindRootPartition() (*Partition, error) {
	var linuxPartitions []Partition

	for _, p := range pt.Partitions {
		// Check for explicit root partition type (GPT)
		if p.TypeGUID == gptTypeLinuxRoot || p.TypeGUID == gptTypeLinuxRootARM64 {
			return &p, nil
		}

		// Collect Linux filesystem partitions
		if p.Type == PartitionTypeLinux {
			linuxPartitions = append(linuxPartitions, p)
		}
	}

	if len(linuxPartitions) == 0 {
		return nil, ErrNoLinuxPartition
	}

	// Return the largest Linux partition
	sort.Slice(linuxPartitions, func(i, j int) bool {
		return linuxPartitions[i].Size > linuxPartitions[j].Size
	})

	return &linuxPartitions[0], nil
}

// GetPartition returns a partition by its 1-based index.
func (pt *PartitionTable) GetPartition(index int) (*Partition, error) {
	for _, p := range pt.Partitions {
		if p.Index == index {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("partition %d not found", index)
}

// LinuxPartitions returns all Linux filesystem partitions.
func (pt *PartitionTable) LinuxPartitions() []Partition {
	var result []Partition
	for _, p := range pt.Partitions {
		if p.Type == PartitionTypeLinux {
			result = append(result, p)
		}
	}
	return result
}

// classifyPartitionType determines the partition type from type bytes.
func classifyPartitionType(typeBytes []byte) PartitionType {
	if len(typeBytes) == 16 {
		// GPT GUID
		guid := formatGUID(typeBytes)
		return gptTypeToPartitionType(guid)
	} else if len(typeBytes) >= 1 {
		// MBR type code
		return mbrTypeToPartitionType(typeBytes[0])
	}
	return PartitionTypeUnknown
}

// formatGUID formats a 16-byte GUID as a string.
func formatGUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	// GPT GUIDs are stored in mixed-endian format
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		b[3], b[2], b[1], b[0],
		b[5], b[4],
		b[7], b[6],
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15])
}

// gptTypeToPartitionType converts a GPT type GUID to PartitionType.
func gptTypeToPartitionType(guid string) PartitionType {
	switch guid {
	case gptTypeLinuxFilesystem, gptTypeLinuxRoot, gptTypeLinuxRootARM64:
		return PartitionTypeLinux
	case gptTypeLinuxLVM:
		return PartitionTypeLinuxLVM
	case gptTypeEFI:
		return PartitionTypeEFI
	case gptTypeLinuxSwap:
		return PartitionTypeSwap
	case gptTypeMSBasic:
		return PartitionTypeNTFS // Could also be FAT32
	default:
		return PartitionTypeUnknown
	}
}

// mbrTypeToPartitionType converts an MBR type code to PartitionType.
func mbrTypeToPartitionType(code byte) PartitionType {
	switch code {
	case mbrTypeLinux:
		return PartitionTypeLinux
	case mbrTypeLinuxLVM:
		return PartitionTypeLinuxLVM
	case mbrTypeLinuxSwap:
		return PartitionTypeSwap
	case mbrTypeEFI:
		return PartitionTypeEFI
	case mbrTypeFAT32, mbrTypeFAT32LBA:
		return PartitionTypeFAT32
	case mbrTypeNTFS:
		return PartitionTypeNTFS
	default:
		return PartitionTypeUnknown
	}
}

var _ types.Driver = (types.Driver)(nil)
