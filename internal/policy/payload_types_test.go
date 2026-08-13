package policy

import (
	"encoding/base64"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	triagev1 "github.com/temporalio/deputy/gen/deputy/triage/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

// payloadAt resolves a path through a ProtoToMap payload, so a case can name one
// value inside a nested message, a repeated field, or a map without restating
// every sibling key EmitUnpopulated adds.
func payloadAt(t *testing.T, payload map[string]any, path ...any) any {
	t.Helper()
	var cur any = payload
	for i, step := range path {
		switch key := step.(type) {
		case string:
			obj, ok := cur.(map[string]any)
			if !ok {
				t.Fatalf("path %v: element %d (%q): have %T, want an object", path, i, key, cur)
			}
			val, ok := obj[key]
			if !ok {
				t.Fatalf("path %v: element %d: no key %q in %v", path, i, key, obj)
			}
			cur = val
		case int:
			list, ok := cur.([]any)
			if !ok {
				t.Fatalf("path %v: element %d (%d): have %T, want a list", path, i, key, cur)
			}
			if key >= len(list) {
				t.Fatalf("path %v: element %d: index %d out of range in %v", path, i, key, list)
			}
			cur = list[key]
		default:
			t.Fatalf("path %v: element %d: unsupported step type %T", path, i, step)
		}
	}
	return cur
}

// TestProtoToMapConvertsByDeclaredType pins the rule the payload conversion
// follows: the field's declared type decides whether a value is a number, not
// the shape of the value.
//
// protojson quotes the 64-bit integer kinds, so those are the only strings that
// carry a number. A version, a subject, or a base64 blob that happens to parse
// as a number is still a string, and a policy comparing it to a string literal
// has to see one.
func TestProtoToMapConvertsByDeclaredType(t *testing.T) {
	created := timestamppb.New(mustTime(t, "2024-01-02T03:04:05Z"))
	// Six bytes whose base64 encoding is all digits, which is what makes a
	// bytes field indistinguishable from a number by shape alone.
	blob, err := base64.StdEncoding.DecodeString("12345678")
	if err != nil {
		t.Fatalf("decode base64 fixture: %v", err)
	}

	tests := []struct {
		name string
		msg  proto.Message
		path []any
		want any
	}{
		{
			name: "two component version stays a string",
			msg:  &dependencyv1.Package{Name: "numpy", Version: "1.21"},
			path: []any{"version"},
			want: "1.21",
		},
		{
			name: "trailing zero version survives",
			msg:  &dependencyv1.Package{Name: "numpy", Version: "1.20"},
			path: []any{"version"},
			want: "1.20",
		},
		{
			name: "major only version survives",
			msg:  &dependencyv1.Package{Name: "numpy", Version: "2.0"},
			path: []any{"version"},
			want: "2.0",
		},
		{
			name: "three component version is unaffected",
			msg:  &dependencyv1.Package{Name: "numpy", Version: "1.21.6"},
			path: []any{"version"},
			want: "1.21.6",
		},
		{
			name: "purl beside the version keeps agreeing with it",
			msg:  &dependencyv1.Package{Name: "numpy", Version: "1.21", Purl: "pkg:pypi/numpy@1.21"},
			path: []any{"purl"},
			want: "pkg:pypi/numpy@1.21",
		},
		{
			name: "twenty one digit subject stays a string",
			msg:  &policyv1.JWTClaims{Sub: "104567890123456789012"},
			path: []any{"sub"},
			want: "104567890123456789012",
		},
		{
			name: "declared int64 parses back to a number",
			msg:  &policyv1.JWTClaims{Exp: 1699999999},
			path: []any{"exp"},
			want: int64(1699999999),
		},
		{
			name: "int64 beyond float53 keeps every digit",
			msg:  &policyv1.JWTClaims{Iat: 9007199254740993},
			path: []any{"iat"},
			want: int64(9007199254740993),
		},
		{
			name: "map with string values keeps its values",
			msg:  &policyv1.JWTClaims{CustomClaims: map[string]string{"repository_owner_id": "12345"}},
			path: []any{"custom_claims", "repository_owner_id"},
			want: "12345",
		},
		{
			name: "map with int32 values holds numbers",
			msg:  &triagev1.PackageSummary{SeverityCounts: map[string]int32{"critical": 2}},
			path: []any{"severity_counts", "critical"},
			want: int64(2),
		},
		{
			name: "second map with string values keeps its values",
			msg: &triagev1.PackageSummary{
				DatabaseSpecific: map[string]string{"review_status": "1.20"},
			},
			path: []any{"database_specific", "review_status"},
			want: "1.20",
		},
		{
			name: "string in a map with message values stays a string",
			msg: &vulnerabilityv1.GetAdvisoriesResponse{
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"GHSA-1234": {Id: "GHSA-1234", Summary: "1.20", Severity: &vulnerabilityv1.Severity{Score: 9}},
				},
			},
			path: []any{"advisories", "GHSA-1234", "summary"},
			want: "1.20",
		},
		{
			name: "double in a map with message values holds a number",
			msg: &vulnerabilityv1.GetAdvisoriesResponse{
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"GHSA-1234": {Id: "GHSA-1234", Summary: "1.20", Severity: &vulnerabilityv1.Severity{Score: 9}},
				},
			},
			path: []any{"advisories", "GHSA-1234", "severity", "score"},
			want: float64(9),
		},
		{
			name: "string in a nested message stays a string",
			msg: &dependencyv1.Package{
				Name:         "numpy",
				LayerDetails: &containerv1.LayerDetails{DiffId: "12345", Index: 3},
			},
			path: []any{"layer_details", "diff_id"},
			want: "12345",
		},
		{
			name: "int32 in a nested message holds a number",
			msg: &dependencyv1.Package{
				Name:         "numpy",
				LayerDetails: &containerv1.LayerDetails{DiffId: "12345", Index: 3},
			},
			path: []any{"layer_details", "index"},
			want: int64(3),
		},
		{
			name: "string in a repeated message stays a string",
			msg: &dependencyv1.Package{
				ManifestRefs: []*dependencyv1.ManifestRef{
					{Path: "12345", Manager: "pip"},
					{Path: "requirements.txt", Manager: "pip"},
				},
			},
			path: []any{"manifest_refs", 0, "path"},
			want: "12345",
		},
		{
			name: "repeated string elements stay strings",
			msg:  &dependencyv1.Package{Licenses: []string{"1.20", "MIT"}},
			path: []any{"licenses", 0},
			want: "1.20",
		},
		{
			name: "raw score text stays a string beside the scored double",
			msg:  &vulnerabilityv1.Severity{Score: 9.8, Raw: "9.8"},
			path: []any{"raw"},
			want: "9.8",
		},
		{
			name: "declared double holds a number",
			msg:  &vulnerabilityv1.Severity{Score: 9.8, Raw: "9.8"},
			path: []any{"score"},
			want: 9.8,
		},
		{
			// protojson writes a whole-numbered double with no decimal point, so
			// this is where reading the value's shape would leave the Go type
			// depending on the score: 9.8 a double, 9.0 an integer, and score / 2
			// integer division for half the CVSS scale.
			name: "whole numbered double is still a double",
			msg:  &vulnerabilityv1.Severity{Score: 9},
			path: []any{"score"},
			want: float64(9),
		},
		{
			name: "infinite double holds a number",
			msg:  &vulnerabilityv1.Severity{Score: math.Inf(1)},
			path: []any{"score"},
			want: math.Inf(1),
		},
		{
			name: "negative infinite double holds a number",
			msg:  &vulnerabilityv1.Severity{Score: math.Inf(-1)},
			path: []any{"score"},
			want: math.Inf(-1),
		},
		{
			name: "enum holds its number",
			msg:  &targetv1.Target{Kind: targetv1.TargetKind_TARGET_KIND_DIR},
			path: []any{"kind"},
			want: int64(targetv1.TargetKind_TARGET_KIND_DIR),
		},
		{
			name: "timestamp keeps its RFC 3339 string",
			msg:  &containerv1.ImageMetadata{Created: created},
			path: []any{"created"},
			want: "2024-01-02T03:04:05Z",
		},
		{
			name: "os version with a trailing zero survives",
			msg:  &containerv1.ImageMetadata{OsVersion: "1.20", DockerVersion: "24.0"},
			path: []any{"os_version"},
			want: "1.20",
		},
		{
			name: "declared int64 size parses back to a number",
			msg:  &containerv1.ImageMetadata{Size: 1099511627776},
			path: []any{"size"},
			want: int64(1099511627776),
		},
		{
			name: "string member of a oneof stays a string",
			msg:  &policyv1.PolicySource{Source: &policyv1.PolicySource_Inline{Inline: "1.20"}},
			path: []any{"inline"},
			want: "1.20",
		},
		{
			name: "message member of a oneof is walked",
			msg: &policyv1.EvaluateRequest{
				Input: &policyv1.EvaluateRequest_ScanVulnerability{
					ScanVulnerability: &policyv1.ScanVulnerabilityPolicyInput{
						Pkg: &dependencyv1.Package{Name: "numpy", Version: "1.20"},
					},
				},
			},
			path: []any{"scan_vulnerability", "pkg", "version"},
			want: "1.20",
		},
		{
			name: "bytes keep their base64 text",
			msg: &policyv1.EvaluateRequest{
				Input: &policyv1.EvaluateRequest_CustomPayload{CustomPayload: blob},
			},
			path: []any{"custom_payload"},
			want: "12345678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := ProtoToMap(tt.msg)
			if err != nil {
				t.Fatalf("ProtoToMap: %v", err)
			}
			got := payloadAt(t, payload, tt.path...)
			if got != tt.want {
				t.Errorf("payload%v = %#v (%T), want %#v (%T)", tt.path, got, got, tt.want, tt.want)
			}
		})
	}
}

// TestProtoToMapConvertsNaNScore covers the one float value that needs its own
// test, because NaN never equals itself. A policy comparing a score has to get a
// number rather than the text protojson writes for it.
func TestProtoToMapConvertsNaNScore(t *testing.T) {
	payload, err := ProtoToMap(&vulnerabilityv1.Severity{Score: math.NaN()})
	if err != nil {
		t.Fatalf("ProtoToMap: %v", err)
	}
	score, ok := payload["score"].(float64)
	if !ok {
		t.Fatalf("payload[score] = %#v (%T), want a float64", payload["score"], payload["score"])
	}
	if !math.IsNaN(score) {
		t.Errorf("payload[score] = %v, want NaN", score)
	}
}

// TestProtoToMapConvertsQuotedIntegerShapes covers the field shapes no Deputy
// proto declares today but the walk still has to get right: a repeated 64-bit
// integer, a map whose values are 64-bit integers, and the remaining 64-bit
// kinds protojson quotes. Each is paired with a string-typed sibling holding a
// numeric-looking value, because the point is that cardinality and kind decide
// per field rather than once per document.
func TestProtoToMapConvertsQuotedIntegerShapes(t *testing.T) {
	md := quotedIntegerShapes(t)

	tests := []struct {
		name string
		json string
		want map[string]any
	}{
		{
			name: "quoted integers parse and their string siblings do not",
			json: `{
				"ids": ["7", "9007199254740993"],
				"tags": ["1.20", "2.0"],
				"counters": {"builds": "12", "runs": "0"},
				"labels": {"version": "1.20", "channel": "2"},
				"delta": "-5",
				"checksum": "9007199254740993",
				"offset": "-9007199254740993",
				"total": "18446744073709551615",
				"choice_name": "2.0"
			}`,
			want: map[string]any{
				"ids":      []any{int64(7), int64(9007199254740993)},
				"tags":     []any{"1.20", "2.0"},
				"counters": map[string]any{"builds": int64(12), "runs": int64(0)},
				"labels":   map[string]any{"version": "1.20", "channel": "2"},
				"delta":    int64(-5),
				"checksum": int64(9007199254740993),
				"offset":   int64(-9007199254740993),
				// A uint64 above the int64 range has no CEL integer to land in,
				// so it becomes a float64. That is unchanged by the typed walk
				// and is the one lossy case left.
				"total":       float64(18446744073709551615),
				"choice_name": "2.0",
			},
		},
		{
			name: "integer member of a oneof parses",
			json: `{"choice_id": "11"}`,
			want: map[string]any{
				"ids":         []any{},
				"tags":        []any{},
				"counters":    map[string]any{},
				"labels":      map[string]any{},
				"delta":       int64(0),
				"checksum":    int64(0),
				"offset":      int64(0),
				"total":       int64(0),
				"choice_id":   int64(11),
				"choice_name": nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := dynamicpb.NewMessage(md)
			if err := protojson.Unmarshal([]byte(tt.json), msg); err != nil {
				t.Fatalf("protojson.Unmarshal: %v", err)
			}
			got, err := ProtoToMap(msg)
			if err != nil {
				t.Fatalf("ProtoToMap: %v", err)
			}
			// An unset oneof member is absent rather than null; naming it in
			// want documents that, and removeNullValues deletes nulls anyway.
			want := make(map[string]any, len(tt.want))
			for k, v := range tt.want {
				if v == nil {
					continue
				}
				want[k] = v
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("ProtoToMap mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestProtoToMapConvertsSchemalessValues covers the well-known types where a
// number genuinely is a number and no field kind applies: Struct, Value and
// ListValue carry JSON, and an Any carries whatever its payload declares.
func TestProtoToMapConvertsSchemalessValues(t *testing.T) {
	t.Run("struct numbers stay numbers and struct strings stay strings", func(t *testing.T) {
		props, err := structpb.NewStruct(map[string]any{
			"count":   3,
			"ratio":   0.5,
			"version": "1.20",
			"mixed":   []any{1, "12"},
			"nested":  map[string]any{"build": 7, "tag": "2.0"},
		})
		if err != nil {
			t.Fatalf("structpb.NewStruct: %v", err)
		}
		got, err := ProtoToMap(props)
		if err != nil {
			t.Fatalf("ProtoToMap: %v", err)
		}
		want := map[string]any{
			"count":   int64(3),
			"ratio":   0.5,
			"version": "1.20",
			"mixed":   []any{int64(1), "12"},
			"nested":  map[string]any{"build": int64(7), "tag": "2.0"},
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("ProtoToMap mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("any payload is walked with its own descriptor", func(t *testing.T) {
		packed, err := anypb.New(&dependencyv1.Package{Name: "numpy", Version: "1.20"})
		if err != nil {
			t.Fatalf("anypb.New: %v", err)
		}
		got, err := ProtoToMap(packed)
		if err != nil {
			t.Fatalf("ProtoToMap: %v", err)
		}
		if want := "type.googleapis.com/deputy.dependency.v1.Package"; got["@type"] != want {
			t.Errorf("payload[@type] = %#v, want %#v", got["@type"], want)
		}
		if want := "1.20"; got["version"] != want {
			t.Errorf("payload[version] = %#v (%T), want %#v", got["version"], got["version"], want)
		}
	})

	t.Run("any payload with its own json form is walked under value", func(t *testing.T) {
		packed, err := anypb.New(wrapperspb.Int64(9007199254740993))
		if err != nil {
			t.Fatalf("anypb.New: %v", err)
		}
		got, err := ProtoToMap(packed)
		if err != nil {
			t.Fatalf("ProtoToMap: %v", err)
		}
		if want := int64(9007199254740993); got["value"] != want {
			t.Errorf("payload[value] = %#v (%T), want %#v", got["value"], got["value"], want)
		}
	})
}

// quotedIntegerShapes builds a message descriptor for the 64-bit integer field
// shapes the Deputy protos do not declare today. It is synthesized rather than
// generated so the walk is tested against the whole of protojson's quoting rule
// instead of only the parts a shipped message happens to use.
func quotedIntegerShapes(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()

	const pkg = "deputy.policy.payloadtest"
	field := func(name string, num int32, typ descriptorpb.FieldDescriptorProto_Type, label descriptorpb.FieldDescriptorProto_Label) *descriptorpb.FieldDescriptorProto {
		return &descriptorpb.FieldDescriptorProto{
			Name:     proto.String(name),
			JsonName: proto.String(name),
			Number:   proto.Int32(num),
			Type:     typ.Enum(),
			Label:    label.Enum(),
		}
	}
	mapEntry := func(name string, valueType descriptorpb.FieldDescriptorProto_Type) *descriptorpb.DescriptorProto {
		return &descriptorpb.DescriptorProto{
			Name: proto.String(name),
			Field: []*descriptorpb.FieldDescriptorProto{
				field("key", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
				field("value", 2, valueType, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
			},
			Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
		}
	}
	mapField := func(name string, num int32, entry string) *descriptorpb.FieldDescriptorProto {
		f := field(name, num, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, descriptorpb.FieldDescriptorProto_LABEL_REPEATED)
		f.TypeName = proto.String("." + pkg + ".Shapes." + entry)
		return f
	}
	oneofMember := func(f *descriptorpb.FieldDescriptorProto) *descriptorpb.FieldDescriptorProto {
		f.OneofIndex = proto.Int32(0)
		return f
	}

	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("deputy/policy/payloadtest.proto"),
		Package: proto.String(pkg),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Shapes"),
			Field: []*descriptorpb.FieldDescriptorProto{
				field("ids", 1, descriptorpb.FieldDescriptorProto_TYPE_INT64, descriptorpb.FieldDescriptorProto_LABEL_REPEATED),
				field("tags", 2, descriptorpb.FieldDescriptorProto_TYPE_STRING, descriptorpb.FieldDescriptorProto_LABEL_REPEATED),
				mapField("counters", 3, "CountersEntry"),
				mapField("labels", 4, "LabelsEntry"),
				field("delta", 5, descriptorpb.FieldDescriptorProto_TYPE_SINT64, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
				field("checksum", 6, descriptorpb.FieldDescriptorProto_TYPE_FIXED64, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
				field("offset", 7, descriptorpb.FieldDescriptorProto_TYPE_SFIXED64, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
				field("total", 8, descriptorpb.FieldDescriptorProto_TYPE_UINT64, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
				oneofMember(field("choice_name", 9, descriptorpb.FieldDescriptorProto_TYPE_STRING, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL)),
				oneofMember(field("choice_id", 10, descriptorpb.FieldDescriptorProto_TYPE_INT64, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL)),
			},
			NestedType: []*descriptorpb.DescriptorProto{
				mapEntry("CountersEntry", descriptorpb.FieldDescriptorProto_TYPE_INT64),
				mapEntry("LabelsEntry", descriptorpb.FieldDescriptorProto_TYPE_STRING),
			},
			OneofDecl: []*descriptorpb.OneofDescriptorProto{{Name: proto.String("choice")}},
		}},
	}

	fd, err := protodesc.NewFile(file, nil)
	if err != nil {
		t.Fatalf("protodesc.NewFile: %v", err)
	}
	return fd.Messages().Get(0)
}

// mustTime parses an RFC 3339 timestamp for a fixture.
func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("time.Parse(%q): %v", value, err)
	}
	return parsed
}

// TestSBOMComponentDeniesExactVersion drives the defect through a shipped
// entrypoint end to end, which is where it was demonstrated: a deny policy
// naming the exact version an author would copy out of an SBOM has to fire, and
// a version the policy does not name has to pass.
func TestSBOMComponentDeniesExactVersion(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		version  string
		wantDeny bool
	}{
		{name: "equality on a two component version", body: `pkg.version == "1.21"`, version: "1.21", wantDeny: true},
		{name: "equality on a trailing zero version", body: `pkg.version == "1.20"`, version: "1.20", wantDeny: true},
		{name: "equality on a major only version", body: `pkg.version == "2.0"`, version: "2.0", wantDeny: true},
		{name: "equality on a three component version", body: `pkg.version == "1.21.6"`, version: "1.21.6", wantDeny: true},
		{name: "equality does not fire for another version", body: `pkg.version == "1.20"`, version: "1.21", wantDeny: false},
		{name: "prefix match on a two component version", body: `pkg.version.startsWith("1.2")`, version: "1.21", wantDeny: true},
		{name: "prefix match with the v prefix an author writes", body: `("v" + pkg.version) == "v1.21"`, version: "1.21", wantDeny: true},
		{name: "ordering against a version baseline", body: `pkg.version < "1.21"`, version: "1.20", wantDeny: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`%s ? [{"action": "deny", "reason": "version denied"}] : []`, tt.body)
			engine, err := NewEngine([]Source{{Name: "deny-exact-version", Body: body}})
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			input := &policyv1.SbomComponentPolicyInput{
				Pkg: &dependencyv1.Package{
					Name:      "numpy",
					Version:   tt.version,
					Ecosystem: "pypi",
					Purl:      "pkg:pypi/numpy@" + tt.version,
				},
				Env: &policyv1.Environment{Command: "sbom", Entrypoint: string(EntrypointSBOMComponent)},
			}
			actions, err := engine.EvaluateAll(t.Context(), input, "sbom", string(EntrypointSBOMComponent))
			if err != nil {
				t.Fatalf("EvaluateAll(version=%q): %v", tt.version, err)
			}
			denied := false
			for _, action := range actions {
				if ActionTypeIs(action.Type, ActionDeny) {
					denied = true
				}
			}
			if denied != tt.wantDeny {
				t.Errorf("%s against version %q denied = %v, want %v (actions %+v)", tt.body, tt.version, denied, tt.wantDeny, actions)
			}
		})
	}
}

// TestServiceRequestJWTClaimTypes drives the JWT half of the defect through a
// service entrypoint: a subject that is all digits has to behave as the string
// the token carried, a declared int64 claim has to stay comparable to a numeric
// literal, and the custom claim flattening that makes jwt.roles iterable has to
// keep working over values that are strings again.
func TestServiceRequestJWTClaimTypes(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		jwt      *policyv1.JWTClaims
		wantDeny bool
	}{
		{
			name:     "equality against a twenty one digit subject",
			body:     `jwt.sub == "104567890123456789012"`,
			jwt:      &policyv1.JWTClaims{Sub: "104567890123456789012"},
			wantDeny: true,
		},
		{
			name:     "prefix match on a twenty one digit subject",
			body:     `jwt.sub.startsWith("1045")`,
			jwt:      &policyv1.JWTClaims{Sub: "104567890123456789012"},
			wantDeny: true,
		},
		{
			name:     "declared int64 claim compares to a numeric literal",
			body:     `jwt.exp == 1699999999`,
			jwt:      &policyv1.JWTClaims{Sub: "104567890123456789012", Exp: 1699999999},
			wantDeny: true,
		},
		{
			name:     "bracketed claim list stays iterable",
			body:     `jwt.roles.exists(r, r == "scanner")`,
			jwt:      &policyv1.JWTClaims{Sub: "user@example.com", CustomClaims: map[string]string{"roles": "[scanner security]"}},
			wantDeny: true,
		},
		{
			name:     "comma separated claim list stays iterable",
			body:     `jwt.roles.exists(r, r == "scanner")`,
			jwt:      &policyv1.JWTClaims{Sub: "user@example.com", CustomClaims: map[string]string{"roles": "admin,scanner"}},
			wantDeny: true,
		},
		{
			name:     "numeric custom claim is the string the schema declares",
			body:     `jwt.repository_owner_id == "12345"`,
			jwt:      &policyv1.JWTClaims{Sub: "repo:acme/app:ref:refs/heads/main", CustomClaims: map[string]string{"repository_owner_id": "12345"}},
			wantDeny: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`%s ? [{"action": "deny", "reason": "identity denied"}] : []`, tt.body)
			engine, err := NewEngine([]Source{{Name: "jwt-claim-types", Body: body}})
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			input := serviceRequestInput[EntrypointServiceScanRequest](tt.jwt, "/deputy.test.v1.TestService/Probe", "github.com/acme/app")
			actions, err := engine.EvaluateAll(t.Context(), input, "server", string(EntrypointServiceScanRequest))
			if err != nil {
				t.Fatalf("EvaluateAll: %v", err)
			}
			denied := false
			for _, action := range actions {
				if ActionTypeIs(action.Type, ActionDeny) {
					denied = true
				}
			}
			if denied != tt.wantDeny {
				t.Errorf("%s denied = %v, want %v (actions %+v)", tt.body, denied, tt.wantDeny, actions)
			}
		})
	}
}
