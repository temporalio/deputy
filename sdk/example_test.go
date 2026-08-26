package sdk_test

import (
	"context"
	"fmt"
	"log"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	"github.com/temporalio/deputy/sdk"
)

// These examples intentionally omit Output comments. This keeps operations
// that need a live service compile-checked without executing them in tests.

func Example() {
	ctx := context.Background()
	client, err := sdk.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	result, err := client.Scan(ctx, ".")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Found %d findings\n", len(result.GetFindings()))
}

func ExampleConnectToServer() {
	ctx := context.Background()
	client, err := sdk.ConnectToServer(ctx, "https://deputy.example.com:8090")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}

func ExampleConnectToServerWithAuth() {
	ctx := context.Background()
	client, err := sdk.ConnectToServerWithAuth(
		ctx,
		"https://deputy.example.com:8090",
		"my-token",
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}

func ExampleConnectToDaemon() {
	ctx := context.Background()

	client, err := sdk.ConnectToDaemon(ctx, "") // Use the default socket.
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	customClient, err := sdk.ConnectToDaemon(ctx, "/var/run/deputy.sock")
	if err != nil {
		log.Fatal(err)
	}
	defer customClient.Close()
}

func ExampleClient_BuildGraph() {
	ctx := context.Background()
	client, err := sdk.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	graph, err := client.BuildGraph(ctx, ".", nil)
	if err != nil {
		log.Fatal(err)
	}
	for _, node := range graph.GetNodes() {
		fmt.Printf("%s@%s (depth: %d)\n", node.GetName(), node.GetVersion(), node.GetDepth())
	}
}

func ExampleClient_WhyDependency() {
	ctx := context.Background()
	client, err := sdk.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	why, err := client.WhyDependency(ctx, ".", "golang.org/x/crypto")
	if err != nil {
		log.Fatal(err)
	}
	for _, path := range why.GetPaths() {
		fmt.Printf("Path (length %d): ", path.GetLength())
		for _, node := range path.GetNodes() {
			fmt.Printf("%s -> ", node.GetName())
		}
		fmt.Println()
	}
}

func ExampleClient_DiffPackages() {
	ctx := context.Background()
	client, err := sdk.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	diff, err := client.DiffPackages(ctx, "main", "HEAD")
	if err != nil {
		log.Fatal(err)
	}
	for _, change := range diff.GetChanges() {
		fmt.Printf("%s: %s %s -> %s\n",
			change.GetChangeKind(), change.GetPackage().GetName(),
			change.GetBaseVersion(), change.GetTargetVersion())
	}
}

func ExampleClient_DiffVulnerabilities() {
	ctx := context.Background()
	client, err := sdk.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	diff, err := client.DiffVulnerabilities(ctx, "v1.0.0", "v2.0.0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Added: %d, Fixed: %d\n",
		len(diff.GetAddedVulnerabilities()),
		len(diff.GetRemovedVulnerabilities()))
}

func ExampleClient_DiffContainerImages() {
	ctx := context.Background()
	client, err := sdk.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	diff, err := client.DiffContainerImages(ctx, "nginx:1.24", "nginx:1.25")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Package changes: %d\n", len(diff.GetPackageChanges()))
	if summary := diff.GetSummary(); summary != nil {
		fmt.Printf("Packages added: %d\n", summary.GetPackagesAdded())
	}
}

func ExampleClient_ScanSecrets() {
	ctx := context.Background()
	client, err := sdk.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	result, err := client.ScanSecrets(ctx, ".", nil)
	if err != nil {
		log.Fatal(err)
	}
	for _, finding := range result.GetFindings() {
		fmt.Printf("%s: %s in %s:%d\n",
			finding.GetType(), finding.GetDescription(),
			finding.GetLocation().GetFile(), finding.GetLocation().GetLine())
	}
}

func ExampleClient_ListDetectors() {
	ctx := context.Background()
	client, err := sdk.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	detectors, err := client.ListDetectors(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, detector := range detectors.GetDetectors() {
		fmt.Printf("%s: %s\n", detector.GetId(), detector.GetDescription())
	}
}

func ExampleClient_EvaluatePolicy() {
	ctx := context.Background()
	client, err := sdk.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	scanResult, err := client.Scan(ctx, ".")
	if err != nil {
		log.Fatal(err)
	}
	policy := sdk.NewInlinePolicy(`
policies:
  - name: block-critical
    rules:
      - action: deny
        when: vulnerabilities.exists(v, v.advisory.severity.level == severity.critical)
`)
	result, err := client.EvaluatePolicy(
		ctx,
		[]*sdk.PolicySource{policy},
		&policyv1.ScanReportPolicyInput{
			Vulnerabilities: scanResult.GetFindings(),
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.GetOutcome())
}

func ExampleClient_EvaluatePolicyForVulnerability() {
	ctx := context.Background()
	client, err := sdk.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	scanResult, err := client.Scan(ctx, ".")
	if err != nil {
		log.Fatal(err)
	}
	policies := []*sdk.PolicySource{sdk.NewInlinePolicy(`
policies:
  - name: block-critical
    rules:
      - action: deny
        when: vulnerability.advisory.severity.level == severity.critical
`)}
	for _, finding := range scanResult.GetFindings() {
		result, err := client.EvaluatePolicyForVulnerability(ctx, policies, finding)
		if err != nil {
			log.Fatalf("evaluate policy for %s: %v", finding.GetAdvisoryId(), err)
		}
		if result.GetOutcome() == sdk.ActionDeny {
			fmt.Printf("Denied vulnerability %s\n", finding.GetAdvisoryId())
		}
	}
}

func ExampleClient_ValidatePolicy() {
	ctx := context.Background()
	client, err := sdk.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	policy := sdk.NewInlinePolicy(`
policies:
  - name: block-critical
    rules:
      - action: deny
        when: vulnerabilities.exists(v, v.advisory.severity.level == severity.critical)
`)
	result, err := client.ValidatePolicy(ctx, []*sdk.PolicySource{policy})
	if err != nil {
		log.Fatal(err)
	}
	if !result.GetValid() {
		for _, validationErr := range result.GetErrors() {
			fmt.Printf("Error in %s: %s\n", validationErr.GetPolicyName(), validationErr.GetMessage())
		}
	}
}

func ExampleClient_ListEntrypoints() {
	ctx := context.Background()
	client, err := sdk.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	entrypoints, err := client.ListEntrypoints(ctx, "")
	if err != nil {
		log.Fatal(err)
	}
	for _, entrypoint := range entrypoints.GetEntrypoints() {
		fmt.Printf("%s (%s): %s\n",
			entrypoint.GetName(), entrypoint.GetCategory(), entrypoint.GetDescription())
	}
}

func ExampleOptions() {
	ctx := context.Background()
	client, err := sdk.NewClientWithOptions(ctx, sdk.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	remoteClient, err := sdk.NewClientWithOptions(ctx, sdk.Options{
		Mode:          sdk.ModeRemote,
		ForceMode:     true,
		ServerAddress: "https://deputy.example.com:8090",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer remoteClient.Close()
}
