package mcp

import (
	"maps"
	"slices"
	"testing"

	mcpv1 "github.com/temporalio/deputy/gen/deputy/mcp/v1"
	"github.com/temporalio/deputy/internal/mcp/protoschema"
	"github.com/temporalio/deputy/internal/policy"
)

// TestListPolicyEntrypointsCategoryEnumMatchesRegistry pins the proto's static
// category list to the canonical policy registry. The mcp.v1 request declares
// the accepted categories as a buf.validate string.in list (the source of the
// advertised schema enum and of protovalidate enforcement); this test makes it
// impossible to add or rename a policy category without updating the proto.
func TestListPolicyEntrypointsCategoryEnumMatchesRegistry(t *testing.T) {
	schema, err := protoschema.ForMessage(
		(&mcpv1.ListPolicyEntrypointsRequest{}).ProtoReflect().Descriptor(),
		protoschema.Options{Input: true},
	)
	if err != nil {
		t.Fatalf("derive input schema: %v", err)
	}

	category, ok := schema.Properties["category"]
	if !ok {
		t.Fatal("input schema has no category property")
	}

	got := make([]string, 0, len(category.Enum))
	for _, v := range category.Enum {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("category enum value %v is not a string", v)
		}
		got = append(got, s)
	}

	want := append(slices.Clone(policy.Categories()), slices.Sorted(maps.Keys(policy.CategoryAliases()))...)
	if !slices.Equal(got, want) {
		t.Fatalf("proto category enum drifted from the policy registry:\n got: %v\nwant: %v\nupdate the string.in list on ListPolicyEntrypointsRequest.category", got, want)
	}
}
