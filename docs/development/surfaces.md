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
- **Vocabulary** is entirely ours and should derive from descriptors: the variables bound at each entrypoint, the fields reachable on them, the enum values. It does not (#182). `severityConstants` and `scopeConstants` in [`internal/policy/evaluator.go`](../../internal/policy/evaluator.go) are hand-written, and they disagree with each other: `severity.critical` is lowercase and `scope.RUNTIME` is uppercase (#182). The cost of that shows in the tooling. The LSP taught uppercase for both until #144, so accepting a severity completion produced a policy that failed at evaluation with `no such key: CRITICAL`; the fix was to have the completion read the runtime map (`policy.SeverityConstantNames`) instead of a second list. Scope is still the second list, spelled out in `internal/policy/lsp/completions.go`, correct only because nobody has changed `scopeConstants` since. Both enums exist in proto, but they do not derive the same way, and that difference is the work rather than a detail of it. `severityConstants` binds real `SeverityLevel` values from [`api/deputy/vulnerability/v1/vulnerability.proto`](../../api/deputy/vulnerability/v1/vulnerability.proto), so its values come from the descriptor unchanged. Its keys do not, and that is the part to write down: the descriptor spells the members `SEVERITY_LEVEL_CRITICAL` while the public vocabulary is `severity.critical`, so the projection is an explicit prefix strip and lowercasing. A generator that maps the descriptor names straight across regenerates the spelling #144 removed, and the failure is at evaluation, not compile: `severity.CRITICAL` fails with `no such key: CRITICAL`. `scopeConstants` does not derive at all: the policy-facing field is `string scope` on `GraphEdge` in [`api/deputy/policy/v1/policy.proto`](../../api/deputy/policy/v1/policy.proto), the `Scope` enum lives on the separate graph service model in [`api/deputy/graph/v1/service.proto`](../../api/deputy/graph/v1/service.proto), and the runtime binds `scope.RUNTIME` to the string `"runtime"`. Generating the enum's numeric value would break every comparison written against those strings, and generating a lowercase string means an explicit `SCOPE_RUNTIME` -> `"runtime"` projection that the policy descriptor does not express. Deriving this vocabulary means picking that projection deliberately, or moving the policy input onto the enum first.
- **Standard library** is the affordance layer: helpers that express something the language cannot.

The standard library needs an admission test, because every addition is surface area a human or a model must learn, and unused surface actively misleads:

> A helper earns its place if it expresses something the language cannot, or if it centralizes a decision that a policy author would otherwise get silently wrong. Abbreviating something the language already says clearly is surface area, not a feature.

The first clause is narrower than it sounds, which is worth stating because the obvious phrasing of this rule admits almost nothing. The environment enables `ext.Strings`, `ext.Lists`, `ext.Math`, and `ext.Encoders`, so `split`, `indexOf`, `substring`, and `join` are all available, and most parsing is expressible if you are willing to write it out. `levenshtein()` is the honest example of the first clause: CEL has bounded comprehensions but no recursion, so an edit distance cannot be written in it at all.

`imageRef()` earns its place under the second clause. Resolving an implicit `docker.io` and telling a registry port from a tag is expressible with string operations, but a hand-rolled version that splits on `:` treats `localhost:5000/app` as a tag, and the resulting rule does not match and does not error. In a security control, a wrong answer that looks like a clean pass is the failure mode worth spending surface area to prevent.

`isCritical()` earns nothing: it abbreviates `== severity.critical`, and no shipped policy uses it.

`age()` is the case worth naming, because it looks like it earns its place and does not. It is `now() - timestamp(x)` with one overload missing, so `age(image.metadata.created)` fails at evaluation where the expression it abbreviates succeeds (#179). An abbreviation narrower than the thing it abbreviates is worse than no helper, because it looks like the safe choice.

**Rule:** design the bundle grammar deliberately (it is ours, and the spec is part of the change), derive the vocabulary, apply the admission test to the standard library, and declare that standard library in one machine-readable place so tooling derives from it too.

### 4. Foreign contracts

The package-manager proxies.

Deputy does not design the npm registry protocol, the Go module proxy protocol, or the OCI distribution spec. It conforms to them. These are adapters with conformance tests, not design surfaces.

They carry one thing that *is* ours: the extension band, the `X-Deputy-*` response headers. These are domain objects projected onto HTTP, and they should be derived and validated like any other projection rather than assembled from string literals.

The prefix is not one contract though, and treating it as one is how a derived replacement would conflate them. There are at least four families, from independent sources:

| family | source | when |
| --- | --- | --- |
| policy decision and package coordinates | `internal/proxy/policy.go` | on a policy refusal |
| mutable tag refusal | `internal/proxy/oci.go` | on a refused mutable tag |
| authentication errors | `internal/proxy/auth_middleware.go` | on an auth failure |
| digest pinning audit | `internal/proxy/oci_toctou.go` | including on success |

The last breaks the simple reading: `X-Deputy-Pinned-Digest` and `X-Deputy-Digest-Pinning` describe what the proxy did, not why it said no. `internal/cli/cmd/proxy_exec.go` is a consumer and parses the first family back.

The second is why this is a table of four rather than a note on one. `oci.go` reaches the first family through the `blockMeta` it hands the shared writer, but its mutable-tag refusal is a separate exit that never goes through that writer: it sets `X-Deputy-Mutable-Tag-Blocked`, `X-Deputy-Ecosystem`, `X-Deputy-Package`, and `X-Deputy-Version`, and no `X-Deputy-Policy`, so it is a refusal that names no policy. It also spells the package coordinate differently. The policy family writes `X-Deputy-Name`, which is the name `proxy_exec.go` reads; `X-Deputy-Package` is written at that one line and read nowhere in the repository, so a blocked mutable tag is already recorded with an empty package name. A refactor that read this table as one contract would carry that incompatible vocabulary forward, or drop the refusal entirely. Unify the headers and the consumer, or model it as its own message; do not fold it into the first row.

**Rule:** conform to the foreign contract, and treat each extension family as a projection of its own domain message. One message per family, not one for the prefix.

### Where configuration fits

Configuration is an ergonomic projection, kind 2, with one difference worth stating plainly: its root is not proto. `internal/config.Config` is a Go struct carrying `yaml` and `json` tags, and the file schema, the `DEPUTY_*` environment variables, and the tables in [`docs/reference/configuration.md`](../reference/configuration.md) are three hand-maintained projections of it. That it did not obviously belong to any of the four kinds is part of why it drifted: no category meant no rule, no derivation mechanism, and no correspondence test.

Nothing ties the reference to the struct. No test reads `configuration.md`, which is how it came to document an entire `sbom` section (`sbom.format`, `sbom.enrich_licenses`, `sbom.license_source`) with no config field behind it; the only SBOM knob that exists is `performance.sbom_enrich_concurrency`.

**Rule:** the same as any other ergonomic projection. The struct is the contract until the contract moves to proto, so derive the reference tables and the environment variable list from it and add a correspondence test that fails when a documented key has no field, or a field no documented key. Adding a setting should be one edit, not three.

## Why this matters, empirically

Auditing the surfaces split them by direction, if not by outcome. Derived surfaces were faithful to their source. Hand-maintained ones had mostly drifted, offering functions nothing registers, fields that exist on no message, and configuration sections that do not exist. Faithful is not the same as correct, and the difference is the whole point of the next section.

The case that decides the design is the policy entrypoint reference. It **is** generated, and it was still publishing variables that crash the proxy, because the source it derived from was wrong. The same generated file advertises scan helpers that no CEL environment registers (#180). Generation was faithful both times; `helpersByCategory` in `internal/policy/helpers.go` is a hand list, and it was copied accurately.

> Generation propagates correctness and incorrectness equally. Deriving from a wrong root is not better than copying by hand.

So generation is necessary and not sufficient. The root needs a contract test: one that fails when a binding profile declares a variable the runtime cannot supply.

The first version of that test landed in #138. [`internal/policy/bindings_test.go`](../../internal/policy/bindings_test.go) compares each profile against the names the CEL environment declares, and pins the names that still fail in `undeclaredBindingVars` so the gap is enforced at its current size and cannot grow quietly.

It is not the whole contract, and the test says so itself. The environment is one flat list shared by every entrypoint and every variable in it is `DynType`, so a name it declares may still be unbound at the entrypoint advertising it. Declared is necessary and not sufficient, and the profile can also advertise a name no message carries: `go_artifact_request` offers an optional `licenses` that `GoArtifactRequestPolicyInput` has no field for.

The payload is the real root, and the thing to get right is that **a root is an evaluation route, not an entrypoint**. Filing each profile under one payload kind is the mistake, because a profile can be reached by more than one route with a different payload shape on each.

`scan_report` is the example. It has a typed root through `PolicyHandler.buildActivation` in [`internal/server/policy_handler.go`](../../internal/server/policy_handler.go), which hands `Engine.EvaluateAll` a `*ScanReportPolicyInput`, and a map-backed root in `internal/cli/cmd/scan.go`. Both are live. A guard assuming one payload per profile checks one and leaves the other unguarded.

Routes come in three kinds:

- **Typed proto**, built by a payload builder such as `buildPolicyInput` or `buildPolicyPayload`. The payload can be checked against a descriptor, but a route is the payload *and* the command and entrypoint it evaluates under, and not every route passes them. The service interceptor in [`internal/server/server.go`](../../internal/server/server.go) reaches `Engine.EvaluateAll` with `("", "")`, and `shouldSkip` applies each filter only when its argument is non-empty, so a policy restricted to one entrypoint also runs on every other service procedure. The filter is not overridden, it is never consulted. A descriptor-only guard cannot see this, so a route has to record its filter arguments beside its payload.
- **Map assembled at the call site**, via `EvaluateAllMap`. Not only the CLI: `internal/sandbox/manager.go` is a caller too, so `sandbox_execution` is map-backed and has nothing to do with the CLI. The guard here is two-part: the profile against the descriptor where a typed input exists, plus a test that the assembled map supplies what the descriptor declares.
- **No route at all.** Some profiles have no evaluator anywhere, yet are still published in the generated reference and offered by the MCP tool, so a policy written against one lints clean and never runs (#189). A contract test pointed at every declared profile would go looking for builders that do not exist, which is why knowing which profiles are live is a prerequisite for the guard rather than a detail of it.

`PolicyService.Evaluate` shows why even a typed route needs more than its payload descriptor. Two of its advertised inputs are not honored: `EvaluateRequest.custom_payload` (field 99) has no case in `buildActivation`, so selecting it returns `no evaluation input provided`, and `EvaluateRequest.entrypoints` (field 20) is never read at all, so a caller asking to evaluate a specific entrypoint gets whichever one the input variant implies. A descriptor check sees both fields and concludes the route is fine.

**A descriptor proves a field can exist, not that a route supplies it.** `scan_report` marks `env` required, `PolicyService.Evaluate` accepts a `ScanReportPolicyInput` with `env` unset, nothing validates required fields on that route, and the conversion does not restore it. `ProtoToMap` marshals with `EmitUnpopulated: true` and then strips nulls, so an empty scalar or an empty list survives as a key while a nil message such as `env` disappears entirely, which is deliberate: `has()` returns true for a key holding null. A policy reading `env.command` then fails at evaluation while the descriptor-only check passes. So the guard has to exercise a payload the route actually accepts and assert the required bindings survive the conversion as the conversion actually behaves, while still allowing optional ones to be absent.

One more thing a descriptor check has to handle before it can be written: **the profile vocabulary and the descriptor vocabulary are not the same**. `imageVars` in `bindings.go` advertises both `image` and `image_info`, `scan.go` supplies both deliberately for compatibility, and the proto declares only `image`. A guard comparing names to descriptor fields would fail on a runtime binding that is correct. So the design needs either an explicit derived alias mapping, or a migration of the runtime and profile onto the descriptor vocabulary first. That choice is part of the work, not a detail to discover during it.

A warning for anyone repeating this audit, learned the hard way. No obvious search answers it. Grepping the `Entrypoint*` Go constants misses entrypoints named by string literal; grepping the literals turns up doc comments and REPL strings that are not evaluators; and enumerating entrypoints is not the same as enumerating routes, since one profile can have several and some have none.

That difficulty is the argument of this section turned on itself. **This document states rules; it deliberately carries no inventory.** Every count written here was wrong within a week, because a hand-maintained list of a moving tree is exactly the defect the rest of the page warns about. Current findings live in the issues referenced above, where they can be closed. The inventory should eventually be derived rather than written (#195), and until it is, treat any specific list in prose as out of date.

## Identity

Package identity deserves its own rule, because it crosses every surface and has drifted on several.

A package coordinate has more than one legitimate spelling. `Go` is the display name, `go` the canonical token, `golang` a purl type, and Go versions appear with and without a leading `v` depending on the path that produced them. The registry in [`internal/ecosystem`](../../internal/ecosystem) has the right shape for this: one entry per ecosystem, with `DisplayName`, `OSVName`, and `ScalibrPrefixes` as explicit projections read back through the registry.

It is not finished. `Registration` carries no normalization rules and no purl type, and the package-level `Parse`, `All`, `NormalizeName`, and `NormalizeVersion` are still hardcoded switches in `ecosystem.go`. `Parse` does not even consult the `Aliases` a registration declares. So adding an ecosystem means a registry entry *and* several edits elsewhere, and an entry added on its own will be invisible to parsing and enumeration.

The failures were never missing machinery. `Ecosystem.NormalizeVersion` exists and several packages call it; the policy path did not, so a rule matching `^v1\.` never fired where versions arrived unprefixed. Correctness was opt-in per caller, and that drifts as callers multiply.

**Rules to design toward.** None of them holds everywhere yet, and each names a specific gap:

- Exactly one canonical form crosses a boundary, and the boundary normalizes rather than trusting its callers. The policy boundary does not: `buildPolicyInput` in [`internal/proxy/handler.go`](../../internal/proxy/handler.go) copies the requested name and version into the payload exactly as they arrived. #168 moves that normalization onto the three CEL payload boundaries, which is the shape this rule asks for.
- Projections live in the registry. Adding an ecosystem should be one entry, and nothing else should need editing. Until `Parse`, `All`, and the normalization methods read from the registry, adding one still means updating those too.
- Every entry carries every projection, enforced by test, and no projection is hardcoded outside the registry.
- Plugins are producers too. Normalize inbound at every plugin boundary, since those producers cannot be reviewed. `PluginExtractor.Extract` in [`internal/inventory/registry/adapter.go`](../../internal/inventory/registry/adapter.go) copies a plugin's name and version straight into a SCALIBR package, so an unprefixed Go version or a differently cased name enters the inventory unnormalized.

**Direction:** the industry already has a canonical package identity, and Deputy already has `internal/purlx`. Treating ecosystem, name, and version as projections of a purl, rather than as three parallel strings that drift independently, gives the domain one identity type to pass around instead of three strings to keep in sync.

It does not remove the normalization, and it is worth being precise about that. `packageurl-go` preserves the version verbatim, so an unnormalized pair still produces two identities:

```
1.2.3   ->  pkg:golang/github.com/foo/bar@1.2.3
v1.2.3  ->  pkg:golang/github.com/foo/bar@v1.2.3
```

Ecosystem-specific name and version normalization still has to happen before the purl is constructed, or the same duplicate identities simply move into a new representation. What the purl buys is a single place to enforce that, and a type that cannot be assembled without deciding.

## Adding a capability

1. Model it in proto first. It is the domain, not a serialization detail.
2. Let the direct projections regenerate.
3. Decide the ergonomic affordance for the CLI deliberately, and add the correspondence test.
4. For the DSL, derive the vocabulary. Apply the admission test before adding a helper.
5. If it crosses the proxy, decide what the extension band says.
6. If it is configurable, add the field to `internal/config.Config` and let the reference and the environment variable list follow from it, rather than editing the struct, the loader, and the docs separately.
7. Add the contract test at the root, not only at the leaves.

If a capability has to be typed into more than one place, that is the signal something should be derived that is not.

## Choosing a mechanism

- **Runtime protoreflect and the embedded descriptor set** for anything needing proto comments at runtime: MCP descriptions, LSP hovers, generated docs. Note that `protoc-gen-go` strips `SourceCodeInfo`, which is why [`descriptorset.binpb`](../../internal/proto/descriptorset) exists.
- **A Go generator that imports the registry and reads the descriptor set** when the output joins proto data with something only Go knows. Per-entrypoint CEL environment declarations are the strongest candidate: generating them from binding profiles plus descriptors turns unbound variables into compile errors. It has to be a Go generator rather than a protoc plugin, because a plugin receives only descriptors and options, and `BindingProfiles` is a Go map in [`internal/policy/bindings.go`](../../internal/policy/bindings.go). A protoc plugin would have to parse repository Go source to see it, which keeps the second source of truth rather than removing it. `internal/docsgen` already works this way and is the precedent to copy.
- **A custom protoc plugin** only once the metadata it needs lives in proto. Moving entrypoint bindings into proto options would make one possible here, and would be the cleaner end state, but that is a prerequisite rather than a detail.
- **Reflection over the Go struct** for the configuration reference, since that struct is the contract today. The `yaml` and `json` tags already name every key, so the reference tables and the `DEPUTY_*` list can be rendered from them the way `internal/docsgen` renders the entrypoint reference, with the same drift test holding the edge. If configuration ever moves into proto, this becomes an ordinary direct projection and the mechanism above applies instead.
- **Neither** for the ergonomic layer. Generate the contract, hand-write the affordance, and let a drift test hold the edge.
