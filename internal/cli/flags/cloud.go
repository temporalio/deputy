package flags

import (
	"github.com/picatz/deputy/internal/cloud"
	"github.com/spf13/cobra"
)

// AddCloudFlags adds cloud provider flags to a command.
// These flags are used when scanning cloud resources (AWS, Azure, GCP).
func AddCloudFlags(cmd *cobra.Command) {
	cmd.Flags().String("profile", "", "Cloud provider profile name (AWS_PROFILE, AZURE_SUBSCRIPTION_ID, GCP_PROJECT)")
	cmd.Flags().String("region", "", "Cloud provider region (overrides default region)")
	cmd.Flags().String("account", "", "Cloud provider account/subscription/project ID")
}

// CloudOptionsFromCmd extracts cloud options from command flags.
func CloudOptionsFromCmd(cmd *cobra.Command) cloud.Options {
	profile, _ := cmd.Flags().GetString("profile")
	region, _ := cmd.Flags().GetString("region")
	account, _ := cmd.Flags().GetString("account")

	opts := cloud.DefaultOptions()
	opts.Profile = profile
	opts.Region = region
	opts.AccountID = account
	return opts
}
