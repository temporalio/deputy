package aws

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/picatz/deputy/internal/cloud"
	"github.com/picatz/deputy/internal/vmimage"
	"github.com/picatz/deputy/internal/vmimage/fsys"
)

// EBSSnapshot represents an EBS snapshot for scanning.
type EBSSnapshot struct {
	client     *Client
	snapshotID string
	volumeSize int64 // in bytes
	blockSize  int32 // in bytes
	opts       cloud.Options

	// Block cache for smart downloading
	mu     sync.RWMutex
	blocks map[int64][]byte

	// Filesystem (lazily initialized)
	fsys fs.FS
}

// OpenEBSSnapshot opens an EBS snapshot for scanning using the EBS Direct API.
func OpenEBSSnapshot(ctx context.Context, client *Client, snapshotID string, opts cloud.Options) (*EBSSnapshot, error) {
	snap := &EBSSnapshot{
		client:     client,
		snapshotID: snapshotID,
		opts:       opts,
		blocks:     make(map[int64][]byte),
	}

	if err := snap.resolve(ctx); err != nil {
		return nil, err
	}

	return snap, nil
}

// resolve fetches snapshot metadata.
func (s *EBSSnapshot) resolve(ctx context.Context) error {
	// Get snapshot metadata from EC2
	output, err := s.client.EC2().DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
		SnapshotIds: []string{s.snapshotID},
	})
	if err != nil {
		return fmt.Errorf("describe snapshot %s: %w", s.snapshotID, err)
	}

	if len(output.Snapshots) == 0 {
		return fmt.Errorf("%w: snapshot %s", cloud.ErrResourceNotFound, s.snapshotID)
	}

	snapshot := output.Snapshots[0]
	s.volumeSize = int64(aws.ToInt32(snapshot.VolumeSize)) * 1024 * 1024 * 1024 // GB to bytes

	// Get block size from EBS Direct API
	listOutput, err := s.client.EBS().ListSnapshotBlocks(ctx, &ebs.ListSnapshotBlocksInput{
		SnapshotId: aws.String(s.snapshotID),
		MaxResults: aws.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("list snapshot blocks: %w", err)
	}

	s.blockSize = aws.ToInt32(listOutput.BlockSize)
	if s.blockSize == 0 {
		s.blockSize = 512 * 1024 // Default 512KB
	}

	return nil
}

// Provider implements cloud.Resource.
func (s *EBSSnapshot) Provider() cloud.Provider {
	return cloud.ProviderAWS
}

// Type implements cloud.Resource.
func (s *EBSSnapshot) Type() cloud.ResourceType {
	return cloud.ResourceTypeAWSEBSSnapshot
}

// ID implements cloud.Resource.
func (s *EBSSnapshot) ID() string {
	return s.snapshotID
}

// Region implements cloud.Resource.
func (s *EBSSnapshot) Region() string {
	return s.client.Region()
}

// AccountID implements cloud.Resource.
func (s *EBSSnapshot) AccountID() string {
	return s.opts.AccountID
}

// Tags implements cloud.Resource.
func (s *EBSSnapshot) Tags() map[string]string {
	return nil // Could fetch from EC2 DescribeSnapshots
}

// Name implements cloud.Resource.
func (s *EBSSnapshot) Name() string {
	return s.snapshotID
}

// FS implements cloud.Resource.
func (s *EBSSnapshot) FS(ctx context.Context) (fs.FS, error) {
	if s.fsys != nil {
		return s.fsys, nil
	}

	// Create a DiskImage-compatible reader for vmimage
	reader := &ebsReader{snapshot: s, ctx: ctx}

	// Parse partition table
	pt, err := vmimage.ReadPartitions(reader)
	if err != nil {
		// No partition table - treat as raw filesystem
		fsType, detectErr := fsys.DetectFilesystem(reader, 0)
		if detectErr != nil {
			return nil, fmt.Errorf("detect filesystem: %w", err)
		}
		s.fsys, err = fsys.OpenFilesystem(reader, 0, s.volumeSize, fsType)
		if err != nil {
			return nil, fmt.Errorf("open filesystem: %w", err)
		}
		return s.fsys, nil
	}

	// Find root partition
	partition, err := pt.FindRootPartition()
	if err != nil {
		return nil, fmt.Errorf("find root partition: %w", err)
	}

	// Detect and open filesystem
	fsType, err := fsys.DetectFilesystem(reader, partition.Start)
	if err != nil {
		// Default to ext4 for Linux partitions
		if partition.Type == vmimage.PartitionTypeLinux {
			fsType = fsys.FilesystemExt4
		} else {
			return nil, fmt.Errorf("detect filesystem type: %w", err)
		}
	}

	s.fsys, err = fsys.OpenFilesystem(reader, partition.Start, partition.Size, fsType)
	if err != nil {
		return nil, fmt.Errorf("open filesystem: %w", err)
	}

	return s.fsys, nil
}

// Close implements cloud.Resource.
func (s *EBSSnapshot) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocks = make(map[int64][]byte) // Clear cache
	return nil
}

// Size implements cloud.BlockReader.
func (s *EBSSnapshot) Size() int64 {
	return s.volumeSize
}

// BlockSize implements cloud.BlockReader.
func (s *EBSSnapshot) BlockSize() int64 {
	return int64(s.blockSize)
}

// ebsReader wraps EBSSnapshot to implement vmimage.DiskImage.
type ebsReader struct {
	snapshot *EBSSnapshot
	ctx      context.Context
}

// ReadAt implements io.ReaderAt by fetching blocks from EBS Direct API.
func (r *ebsReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.snapshot.volumeSize {
		return 0, io.EOF
	}

	blockSize := int64(r.snapshot.blockSize)
	startBlock := off / blockSize
	endBlock := (off + int64(len(p)) - 1) / blockSize

	var totalRead int
	for blockIdx := startBlock; blockIdx <= endBlock; blockIdx++ {
		blockData, err := r.snapshot.getBlock(r.ctx, blockIdx)
		if err != nil {
			return totalRead, err
		}

		// Calculate offsets within this block
		blockStart := blockIdx * blockSize
		startInBlock := int64(0)
		if off > blockStart {
			startInBlock = off - blockStart
		}

		// Calculate how much to copy from this block
		endInBlock := blockSize
		remaining := int64(len(p)) - int64(totalRead)
		if endInBlock-startInBlock > remaining {
			endInBlock = startInBlock + remaining
		}

		// Handle sparse blocks (nil data means zeros)
		if blockData == nil {
			copied := int(endInBlock - startInBlock)
			for i := 0; i < copied; i++ {
				p[totalRead+i] = 0
			}
			totalRead += copied
		} else {
			copied := copy(p[totalRead:], blockData[startInBlock:endInBlock])
			totalRead += copied
		}
	}

	return totalRead, nil
}

// Size implements vmimage.DiskImage.
func (r *ebsReader) Size() int64 {
	return r.snapshot.volumeSize
}

// Format implements vmimage.DiskImage.
func (r *ebsReader) Format() string {
	return "ebs"
}

// Close implements vmimage.DiskImage.
func (r *ebsReader) Close() error {
	return nil
}

// getBlock fetches a block from cache or EBS Direct API.
func (s *EBSSnapshot) getBlock(ctx context.Context, blockIdx int64) ([]byte, error) {
	// Check cache first
	s.mu.RLock()
	if data, ok := s.blocks[blockIdx]; ok {
		s.mu.RUnlock()
		return data, nil
	}
	s.mu.RUnlock()

	// Fetch from EBS Direct API
	output, err := s.client.EBS().GetSnapshotBlock(ctx, &ebs.GetSnapshotBlockInput{
		SnapshotId: aws.String(s.snapshotID),
		BlockIndex: aws.Int32(int32(blockIdx)),
		BlockToken: aws.String(""), // Will be filled by ListChangedBlocks if needed
	})
	if err != nil {
		// Block doesn't exist (sparse) - return nil for zeros
		return nil, nil
	}
	defer output.BlockData.Close()

	// Read and decode block data
	data, err := io.ReadAll(output.BlockData)
	if err != nil {
		return nil, fmt.Errorf("read block %d: %w", blockIdx, err)
	}

	// EBS returns base64-encoded data for some block types
	if output.Checksum != nil && len(data) > 0 {
		if decoded, err := base64.StdEncoding.DecodeString(string(data)); err == nil {
			data = decoded
		}
	}

	// Cache the block
	s.mu.Lock()
	s.blocks[blockIdx] = data
	s.mu.Unlock()

	return data, nil
}

// BlockReader returns a cloud.BlockReader for low-level block access.
// This is useful for callers that need direct block-level access to the snapshot.
func (s *EBSSnapshot) BlockReader(ctx context.Context) cloud.BlockReader {
	return &ebsReader{snapshot: s, ctx: ctx}
}

// BlockSize implements cloud.BlockReader on ebsReader.
func (r *ebsReader) BlockSize() int64 {
	return int64(r.snapshot.blockSize)
}

var _ cloud.Resource = (*EBSSnapshot)(nil)
var _ cloud.BlockReader = (*ebsReader)(nil)
var _ vmimage.DiskImage = (*ebsReader)(nil)
