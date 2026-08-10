# Surfaces and the domain

Deputy exposes the same domain through many surfaces: a CLI, a ConnectRPC API, an MCP server, an LSP, a CEL policy DSL, package-manager proxies, and rendered output. Keeping them coherent is not a matter of making them look alike. They are different kinds of thing, and each kind has a different relationship to the domain model.

This note fixes those rules so a new capability can be designed once and projected outward, instead of being typed into six places and drifting.

## The rule

The protos in [`api/deputy`](../../api/deputy) are the domain. Everything a user or an integrator touches is either derived from them, adapted from them, or built on top of them. Which of the three decides how much may be hand-written and what test guards the edge.

## Four kinds of surface

### 1. Direct projections

ConnectRPC service contracts and their transport bindings, MCP tool schemas, the generated policy input reference.

These are the domain re-encoded. They should be generated, and drift is a bug rather than a maintenance chore. Buf emits the Connect bindings under [`gen/deputy`](../../gen/deputy), `internal/mcp/protoschema` derives every MCP tool schema from descriptors, and `internal/docsgen` renders the policy entrypoint reference from proto comments. All three hold up well.

Handler bodies are not part of this. The behavior behind an endpoint (`internal/server/scan_handler.go` and its siblings) is written by hand, as it should be. What is generated is the contract the handler implements, and what this rule forbids is a second, hand-written copy of that contract living somewhere else.

**Rule:** generate the contract. Do not hand-maintain a copy of it.

### 2. Ergonomic projections

The CLI, the TUI, PR comments, human-readable reports.

These need affordances the proto cannot carry: short flag names, sensible defaults, progressive disclosure, color, summary versus detail. The contract still derives (which fields exist, their types, their validation, their help text), but the affordance is designed by hand.

**Rule:** derive the contract, hand-write the ergonomics, and add a correspondence test so the two cannot separate.

### 3. A language over the domain

The CEL policy DSL.

This is the one surface that genuinely is not a projection. It has three parts, and they do not share an owner:

- **Grammar** has two layers. The expression sublanguage is CEL's and is not ours to design. The bundle grammar wrapped around it is entirely ours: `policies`, `vars`, `rules`, actions, modes, entrypoint and command filters, variable ordering, and the validation that rejects a malformed bundle. It lives in [`internal/policy/source.go`](../../internal/policy/source.go) and [`internal/policy/bundle_structured.go`](../../internal/policy/bundle_structured.go) and is specified in [`docs/reference/policy-spec.md`](../reference/policy-spec.md). Most DSL features land in that layer, which means parsing, validation, compatibility, and spec work, not just a CEL expression.
- **Vocabulary** is entirely ours and must derive from descriptors: the variables bound at each entrypoint, the fields reachable on them, the enum values.
- **Standard library** is the affordance layer: helpers that express something the language cannot.

The standard library needs an admission test, because every addition is surface area a human or a model must learn, and unused surface actively misleads:

> A helper earns its place only if it expresses something the language cannot. If it merely abbreviates something the language already says clearly, it is surface area, not a feature.

`age()` earns it (time arithmetic on a domain value). `isCritical()` does not (it abbreviates `== severity.critical`, and the corpus shows nobody uses it).

**Rule:** design the bundle grammar deliberately (it is ours, and the spec is part of the change), derive the vocabulary, apply the admission test to the standard library, and declare that standard library in one machine-readable place so tooling derives from it too.

### 4. Foreign contracts

The package-manager proxies.

Deputy does not design the npm registry protocol, the Go module proxy protocol, or the OCI distribution spec. It conforms to them. These are adapters with conformance tests, not design surfaces.

They carry one thing that *is* ours: the extension band. The `X-Deputy-*` response headers are how a client, a CI job, or an agent learns why an artifact was refused. That is a domain object projected onto HTTP, and it should be derived and validated like any other projection rather than assembled from string literals.

**Rule:** conform to the foreign contract, and treat the extension band as a projection of the domain.

## Why this matters, empirically

Auditing every surface produced a clean split. Derived surfaces were correct. Hand-maintained ones had drifted:

| Surface | Source | Outcome |
| --- | --- | --- |
| MCP tool schemas | descriptors | correct |
| Policy entrypoint reference | descriptors, via `bindings.go` | see below |
| Helper catalog | hand | documents helpers nothing registers |
| REPL schema | hand | offers a function registered nowhere |
| LSP completions | hand | offers fields that exist on no message |
| Config reference | hand | documents an entire section that does not exist |

One nuance decides the whole design. The policy entrypoint reference **is** generated, and it was still publishing variables that crash the proxy, because the source it derived from was wrong.

> Generation propagates correctness and incorrectness equally. Deriving from a wrong root is not better than copying by hand.

So generation is necessary and not sufficient. The root needs a contract test: one that fails when a binding profile declares a variable the runtime cannot supply.

On `main` there is no such test. [`internal/policy/bindings_test.go`](../../internal/policy/bindings_test.go) checks profile membership, descriptions, and a short list of expected variables, none of which reach the payload, which is why `go_artifact_request` still declares an optional `licenses` variable that `GoArtifactRequestPolicyInput` has no field for. A first version is in review, comparing each profile against the variables the CEL environment actually declares. The rule this section argues for is that such a guard belongs at every derivation root, not only this one.

## Identity

Package identity deserves its own rule, because it crosses every surface and has drifted on several.

A package coordinate has more than one legitimate spelling. `Go` is the display name, `go` the canonical token, `golang` a purl type, and Go versions appear with and without a leading `v` depending on the path that produced them. The registry in [`internal/ecosystem`](../../internal/ecosystem) has the right shape for this: one entry per ecosystem, with `DisplayName`, `OSVName`, and `ScalibrPrefixes` as explicit projections read back through the registry.

It is not finished. `Registration` carries no normalization rules and no purl type, and the package-level `Parse`, `All`, `NormalizeName`, and `NormalizeVersion` are still hardcoded switches in `ecosystem.go`. `Parse` does not even consult the `Aliases` a registration declares. So adding an ecosystem today means a registry entry *and* several edits elsewhere, and an entry added on its own will be invisible to parsing and enumeration.

The failures were never missing machinery. `Ecosystem.NormalizeVersion` exists and five packages call it; the policy path did not, so a rule matching `^v1\.` never fired where versions arrived unprefixed. Correctness was opt-in per caller, and that drifts as callers multiply.

**Rules to design toward** (the first and last hold today, the middle two describe where the registry is going):

- Exactly one canonical form crosses a boundary, and the boundary normalizes rather than trusting its callers.
- Projections live in the registry. Adding an ecosystem should be one entry, and nothing else should need editing. Until `Parse`, `All`, and the normalization methods read from the registry, adding one still means updating those too.
- Every entry carries every projection, enforced by test, and no projection is hardcoded outside the registry.
- Plugins are producers too. Normalize inbound at every plugin boundary, since those producers cannot be reviewed.

**Direction:** the industry already has a canonical package identity, and Deputy already has `internal/purlx`. Treating ecosystem, name, and version as projections of a purl, rather than as three parallel strings that drift independently, removes this class rather than fixing instances of it. New surfaces should be designed toward that.

## Adding a capability

1. Model it in proto first. It is the domain, not a serialization detail.
2. Let the direct projections regenerate.
3. Decide the ergonomic affordance for the CLI deliberately, and add the correspondence test.
4. For the DSL, derive the vocabulary. Apply the admission test before adding a helper.
5. If it crosses the proxy, decide what the extension band says.
6. Add the contract test at the root, not only at the leaves.

If a capability has to be typed into more than one place, that is the signal something should be derived that is not.

## Choosing a mechanism

- **Runtime protoreflect and the embedded descriptor set** for anything needing proto comments at runtime: MCP descriptions, LSP hovers, generated docs. Note that `protoc-gen-go` strips `SourceCodeInfo`, which is why [`descriptorset.binpb`](../../internal/proto/descriptorset) exists.
- **A custom protoc plugin** when the output is code that does not exist yet and the mapping is mechanical. Per-entrypoint CEL environment declarations are the strongest candidate: generating them from binding profiles plus descriptors turns unbound variables into compile errors.
- **Neither** for the ergonomic layer. Generate the contract, hand-write the affordance, and let a drift test hold the edge.
