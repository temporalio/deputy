package providers

import (
	cloudv1 "github.com/picatz/deputy/gen/deputy/cloud/v1"
	"github.com/picatz/deputy/internal/targets"
)

// ListOptionsToProto converts a Deputy ListOptions to the proto ListFilter.
// This is used when calling cloud plugins via RPC.
func ListOptionsToProto(opts *targets.ListOptions) *cloudv1.ListFilter {
	if opts == nil {
		return nil
	}

	filter := &cloudv1.ListFilter{
		Tags:          opts.Tags,
		NamePattern:   opts.NamePattern,
		CelExpression: opts.CELExpression,
	}

	if opts.Context != nil {
		filter.Context = ProviderContextToProto(opts.Context)
	}

	// Return nil if effectively empty
	if len(filter.Tags) == 0 && filter.NamePattern == "" &&
		filter.CelExpression == "" && filter.Context == nil {
		return nil
	}

	return filter
}

// OpenOptionsToProto converts a Deputy OpenOptions to the proto OpenOptions.
// This is used when calling cloud plugins via RPC.
func OpenOptionsToProto(opts *targets.OpenOptions) *cloudv1.OpenOptions {
	if opts == nil {
		return nil
	}

	protoOpts := &cloudv1.OpenOptions{
		SmartDownload:    opts.SmartDownload,
		Ecosystems:       opts.Ecosystems,
		Platform:         opts.Platform,
		SkipVerification: opts.SkipVerification,
	}

	if opts.Context != nil {
		protoOpts.Context = ProviderContextToProto(opts.Context)
	}

	return protoOpts
}

// ProviderContextToProto converts a Deputy ProviderContext to the proto ProviderContext.
func ProviderContextToProto(ctx *targets.ProviderContext) *cloudv1.ProviderContext {
	if ctx == nil {
		return nil
	}

	return &cloudv1.ProviderContext{
		AwsRegion:          ctx.AWSRegion,
		AwsOwner:           ctx.AWSOwner,
		GcpProject:         ctx.GCPProject,
		GcpLocation:        ctx.GCPLocation,
		AzureSubscription:  ctx.AzureSubscription,
		AzureResourceGroup: ctx.AzureResourceGroup,
		ScmOrganization:    ctx.Organization,
		Extra:              ctx.Extra,
	}
}

// ListOptionsFromProto converts a proto ListFilter to Deputy ListOptions.
// This is used when receiving options from proto messages.
func ListOptionsFromProto(filter *cloudv1.ListFilter) *targets.ListOptions {
	if filter == nil {
		return nil
	}

	opts := &targets.ListOptions{
		Tags:          filter.Tags,
		NamePattern:   filter.NamePattern,
		CELExpression: filter.CelExpression,
	}

	if filter.Context != nil {
		opts.Context = ProviderContextFromProto(filter.Context)
	}

	return opts
}

// OpenOptionsFromProto converts a proto OpenOptions to Deputy OpenOptions.
// This is used when receiving options from proto messages.
func OpenOptionsFromProto(protoOpts *cloudv1.OpenOptions) *targets.OpenOptions {
	if protoOpts == nil {
		return nil
	}

	opts := &targets.OpenOptions{
		SmartDownload:    protoOpts.SmartDownload,
		Ecosystems:       protoOpts.Ecosystems,
		Platform:         protoOpts.Platform,
		SkipVerification: protoOpts.SkipVerification,
	}

	if protoOpts.Context != nil {
		opts.Context = ProviderContextFromProto(protoOpts.Context)
	}

	return opts
}

// ProviderContextFromProto converts a proto ProviderContext to Deputy ProviderContext.
func ProviderContextFromProto(ctx *cloudv1.ProviderContext) *targets.ProviderContext {
	if ctx == nil {
		return nil
	}

	return &targets.ProviderContext{
		AWSRegion:          ctx.AwsRegion,
		AWSOwner:           ctx.AwsOwner,
		GCPProject:         ctx.GcpProject,
		GCPLocation:        ctx.GcpLocation,
		AzureSubscription:  ctx.AzureSubscription,
		AzureResourceGroup: ctx.AzureResourceGroup,
		Organization:       ctx.ScmOrganization,
		Extra:              ctx.Extra,
	}
}
