# Surfaces and the domain

Deputy exposes the same domain through many surfaces: a CLI, a ConnectRPC API, an MCP server, an LSP, a CEL policy DSL, package-manager proxies, and rendered output. Keeping them coherent is not a matter of making them look alike. They are different kinds of thing, and each kind has a different relationship to the domain model.

This note fixes those rules so a new capability can be designed once and projected outward, instead of being typed into six places and drifting.

## The rule

The protos in [`api/deputy`](../../api/deputy) are the domain. Everything a user or an integrator touches is either derived from them, adapted from them, or built on top of them. Which of the three decides how much may be hand-written and what test guards the edge.

### How to read a claim on this page

The failure this page has repeated is stating an aspiration in the present tense, so a reader takes an edge to be held when nothing holds it. Every claim about what the repository does therefore carries one of three labels:

- **Guarded.** It holds, and a named test fails when it stops holding. The test is named where the claim is made.
- **Convention.** It holds because someone maintained it. Nothing fails when it stops.
- **Direction.** It does not hold. The gap is named, with its issue where one is open.

A **Rule** is never labelled: a rule is what to do, not a report on what the code does. Where the code does not follow one yet, the text above it says so with a label. Unlabelled prose describes code as written, not a property anything preserves.

## Four kinds of surface

### 1. Direct projections

ConnectRPC service contracts and their transport bindings, the plugin wire contracts an extension implements, MCP tool schemas, the generated policy input reference.

These are the domain re-encoded. They should be generated, and drift is a bug rather than a maintenance chore. They do not all stand on the same footing, and the difference is what a reader needs:

- MCP tool schemas are **guarded** from the descriptor onward. `internal/mcp/protoschema` computes them as the server describes a tool, so no schema copy is committed, and `TestToolSchemasFreeOfClientRejectedKeywords` walks `Server.registeredTools` to hold the result inside the MCP client constraints.
- The Connect bindings under [`gen/deputy`](../../gen/deputy) are **convention**. Buf emits them, but the output is committed and no CI job regenerates and diffs the tree, so a proto edited without regenerating fails nothing.
- The policy entrypoint reference is **guarded** by `TestPolicyInputsDocIsGenerated`, and it is not a descriptor projection.

That last one is worth naming precisely, because calling it descriptor-derived hides the drift this page later audits. `PolicyEntrypointsMarkdown` is a joined projection: the entrypoint list, each entrypoint's description, its required and optional variables and their types, and its helper list all come from hand-maintained Go registries in `internal/policy` (`AllEntrypoints`, `BindingProfiles`, `EntrypointHelpers`, and the variable metadata behind `VariableInfoOrDefault`), while descriptors supply only the field tables for proto-backed variable types and the comments in them. The drift test holds the rendering to those sources. It cannot see that a source is wrong, which is exactly how the reference came to publish variables the runtime cannot supply.

Both of those guards stop in the same place, and where they stop is the other half of the label: at the descriptor, which is itself a committed artifact. `mustToolSchemas` takes its descriptors off the generated `mcpv1` Go messages, and the entrypoint reference takes field shapes off the generated packages and comments off [`descriptorset.binpb`](../../internal/proto/descriptorset). Edit a proto under [`api/deputy`](../../api/deputy) and skip the regeneration and every one of these tests goes on inspecting the previous generation and passes, `TestEmbeddedDescriptorSetMatchesGeneratedCode` included, because it compares the embedded set against those same generated packages and holds when both are equally stale. So descriptor to projection is **guarded**, and source proto to descriptor is **convention**, held by whoever remembers to regenerate.

Plugin wire contracts belong here for the same reason the Connect ones do: they are proto in [`api/deputy/plugin/v1`](../../api/deputy/plugin/v1) and [`api/deputy/sandbox/v1`](../../api/deputy/sandbox/v1), and Buf generates the bindings from them, `protoc-gen-pluginrpc-go` for the services a subprocess plugin serves and the Connect output for the sandbox runtime a plugin binds over a socket. What separates them is the consumer. An extractor, an advisory source, or a sandbox runtime can be a program this repository does not build and cannot update, so renumbering a field or dropping a method breaks something no change here can fix.

They are not alone in that, and scoping the obligation to plugins is how the rest gets missed. [`docs/commands/server.md`](../commands/server.md) documents remote ConnectRPC clients and plain HTTP/JSON callers posting to procedures by fully qualified name, so the public service protos have consumers outside this tree too, and renumbering one of their fields breaks those callers with no compile error here either. The obligation follows the consumer, not the binding: every protobuf contract something outside the repository speaks gets the same compatibility decision.

Nothing enforces it, so it is **convention** twice over. `api/buf.yaml` configures `breaking: use: FILE`, but no workflow under [`.github/workflows`](../../.github/workflows) invokes buf at all, for breaking or for anything else, so a wire-incompatible edit reaches a release the same way a compatible one does.

Handler bodies are not part of this. The behavior behind an endpoint (`internal/server/scan_handler.go` and its siblings) is written by hand, as it should be. What is generated is the contract the handler implements, and what this rule forbids is a second, hand-written copy of that contract living somewhere else.

**Rule:** generate the contract. Do not hand-maintain a copy of it. Where a contract has an implementer or a caller outside the repository, changing it is a compatibility decision, and someone runs that check by hand before the change lands, because nothing in CI will run it after.

### 2. Ergonomic projections

The CLI, PR comments, human-readable reports, and the public Go SDK. A TUI belongs here too, but there is no TUI: the only trace of one is a TODO in `internal/cli/cmd/exec_review.go`, so treat it as **Direction** rather than a surface anyone maintains.

These need affordances the proto cannot carry: short flag names, sensible defaults, progressive disclosure, color, summary versus detail. The split that makes them tractable is that the contract derives (which fields exist, their types, their validation) while the affordance is designed by hand.

A command's machine-readable output is not in this category, whatever the command's human output does. `deputy triage --format json` marshals the response message with protojson, so the JSON *is* the proto and belongs with the direct projections above. That is the line to hold when adding a format: a hand-written struct with JSON tags for machine consumption is a new contract nobody agreed to, and it drifts from the one the API already serves.

**Direction:** for the CLI, nothing derives. `internal/cli/cmd/scan.go` declares each Cobra flag by hand with its own default and help string, including prose that restates a domain the proto already owns: `--source` spells out the target kinds and `--ecosystems` spells out the ecosystem list. `scanFlags.toScanRequest` in `internal/cli/cmd/scan_flags.go` then copies the parsed flags into `scanv1.ScanOptions` field by field. Nothing compares the two ends, and nothing exercises that copy either: `toScanRequest` appears in no test, and `TestScanFlags_ScanOptions` is named for a different type, calling `scanFlags.scanOptions()` and asserting on the `internal/inventory.ScanOptions` it returns, so it never reaches the proto at all. Add a field to `scanv1.ScanOptions` or tighten a protovalidate constraint on one and the CLI is unchanged and every test still passes.

The Go SDK in [`sdk`](../../sdk) is the same kind of surface aimed at a program instead of a person, and its affordances are mode selection and short call shapes. Its types cannot drift: they are aliases of the generated messages. Its operations can. `Client.Scan`, `GenerateSBOM`, `EvaluatePolicy`, and their siblings are hand-written wrappers, each naming one procedure and filling in one request literal, so a new RPC gets no method and a new request field gets no way in until someone adds it. `DiffPackages` takes a base and a target and offers no parameter for the `DiffOptions` its request carries. **Direction** here too: the SDK's tests cover mode selection, and nothing relates the wrapper set to the service contract it adapts.

**Rule:** derive the contract, hand-write the ergonomics, and add a correspondence test so the two cannot separate. There is no such test in the tree to copy, so the first surface to follow this rule builds the pattern.

### 3. A language over the domain

The CEL policy DSL.

This is the one surface that genuinely is not a projection. It has three parts, and they do not share an owner:

- **Grammar** has two layers. The expression sublanguage is CEL's and is not ours to design. The bundle grammar wrapped around it is entirely ours: `policies`, `vars`, `rules`, actions, modes, entrypoint and command filters, variable ordering, and the validation that rejects a malformed bundle. It lives in [`internal/policy/source.go`](../../internal/policy/source.go) and [`internal/policy/bundle_structured.go`](../../internal/policy/bundle_structured.go) and is specified in [`docs/reference/policy-spec.md`](../reference/policy-spec.md). Most DSL features land in that layer, which means parsing, validation, compatibility, and spec work, not just a CEL expression.
- **Vocabulary** is entirely ours and should derive from descriptors: the variables bound at each entrypoint, the fields reachable on them, the enum values. That is **direction**, not description; it does not derive (#182). `severityConstants` and `scopeConstants` in [`internal/policy/evaluator.go`](../../internal/policy/evaluator.go) are hand-written, and they disagree with each other: `severity.critical` is lowercase and `scope.RUNTIME` is uppercase (#182). The cost of that shows in the tooling. The LSP taught uppercase for both until #144, so accepting a severity completion produced a policy that failed at evaluation with `no such key: CRITICAL`; the fix was to have the completion read the runtime map (`policy.SeverityConstantNames`) instead of a second list. Scope is still the second list, spelled out in `internal/policy/lsp/completions.go`, correct only because nobody has changed `scopeConstants` since. Both enums exist in proto, but they do not derive the same way, and that difference is the work rather than a detail of it. `severityConstants` binds real `SeverityLevel` values from [`api/deputy/vulnerability/v1/vulnerability.proto`](../../api/deputy/vulnerability/v1/vulnerability.proto), so its values come from the descriptor unchanged. Its keys do not, and that is the part to write down: the descriptor spells the members `SEVERITY_LEVEL_CRITICAL` while the public vocabulary is `severity.critical`, so the projection is an explicit prefix strip and lowercasing. A generator that maps the descriptor names straight across regenerates the spelling #144 removed, and the failure is at evaluation, not compile: `severity.CRITICAL` fails with `no such key: CRITICAL`. `scopeConstants` does not derive at all: the policy-facing field is `string scope` on `GraphEdge` in [`api/deputy/policy/v1/policy.proto`](../../api/deputy/policy/v1/policy.proto), the `Scope` enum lives on the separate graph service model in [`api/deputy/graph/v1/service.proto`](../../api/deputy/graph/v1/service.proto), and the runtime binds `scope.RUNTIME` to the string `"runtime"`. Generating the enum's numeric value would break every comparison written against those strings, and generating a lowercase string means an explicit `SCOPE_RUNTIME` -> `"runtime"` projection that the policy descriptor does not express. Deriving this vocabulary means picking that projection deliberately, or moving the policy input onto the enum first.
- **Standard library** is the affordance layer: helpers that express something the language cannot.

The standard library needs an admission test, because every addition is surface area a human or a model must learn, and unused surface actively misleads:

> A helper earns its place if it expresses something the language cannot, or if it centralizes a decision that a policy author would otherwise get silently wrong. Abbreviating something the language already says clearly is surface area, not a feature.

The first clause is narrower than it sounds, which is worth stating because the obvious phrasing of this rule admits almost nothing. The environment enables `ext.Strings`, `ext.Lists`, `ext.Math`, and `ext.Encoders`, so `split`, `indexOf`, `substring`, and `join` are all available, and most parsing is expressible if you are willing to write it out. `levenshtein()` is the honest example of the first clause: CEL has bounded comprehensions but no recursion, so an edit distance cannot be written in it at all.

`imageRef()` earns its place under the second clause. Resolving an implicit `docker.io` and telling a registry port from a tag is expressible with string operations, but a hand-rolled version that splits on `:` treats `localhost:5000/app` as a tag, and the resulting rule does not match and does not error. In a security control, a wrong answer that looks like a clean pass is the failure mode worth spending surface area to prevent.

`pathLength()` earns nothing. Its binding returns the list's `Size()`, so it is `size(p)` spelled longer, and the expression it replaces is already clear.

`isCritical()` reads like the same case and is not, so the test applies to the binding rather than to the name. It is not `== severity.critical`. It walks `advisory.severity.level` itself and accepts the level as either a number or a string, so on a map-backed payload carrying `"CRITICAL"` the helper returns true where the equality returns false. Whether the normalization earns its place under the second clause is a real question; deleting it as an abbreviation would change which findings match.

`age()` is the case worth naming, because it looks like it earns its place and does not. It is `now() - timestamp(x)` with one overload missing, so `age(image.metadata.created)` fails at evaluation where the expression it abbreviates succeeds (#179). An abbreviation narrower than the thing it abbreviates is worse than no helper, because it looks like the safe choice.

**Rule:** design the bundle grammar deliberately (it is ours, and the spec is part of the change), derive the vocabulary, apply the admission test to the standard library, and declare that standard library in one machine-readable place so tooling derives from it too.

### 4. Foreign contracts

The package-manager proxies.

Deputy does not design the npm registry protocol, the Go module proxy protocol, the OCI distribution spec, or the package-manager protocols beside them. It conforms to them. Every adapter in [`internal/proxy`](../../internal/proxy) named for an ecosystem is one of these, and each has protocol-oriented tests rather than a contract of ours. Read the directory rather than a list here; the point is the obligation, which is the same for all of them and for the next one.

They carry one thing that *is* ours: the extension band, the `X-Deputy-*` response headers. These are domain objects projected onto HTTP, and they should be derived and validated like any other projection. **Direction:** no message describes them. They are written at the point of use, some through named constants and some as bare literals (`w.Header().Set("X-Deputy-Name", meta.Name)` in `internal/proxy/policy.go`), and nothing checks a writer against a reader.

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

**Rule:** the same as any other ergonomic projection. The struct is the contract until the contract moves to proto, so derive the reference tables from it and add a correspondence test that fails when a documented key has no field, or a field no documented key. Adding a setting should be one edit, not a checklist.

**Direction:** all of it. No generator renders those tables and no test reads them, so adding a setting stays the several separate edits enumerated in *Adding a capability* until someone builds the mechanism in *Choosing a mechanism*.

The environment variables are the harder half and need a step first: the binding has to exist as data before it can be derived. It is control flow instead, an `if os.Getenv(...)` per variable spread across `Loader.loadFromEnv` and the section loaders beside it, and the name is not a function of the field. `DEPUTY_PROXY_ADDR` sets `proxy.listen_addr` and `DEPUTY_OSV_CONCURRENCY` sets `performance.osv_concurrency`, so neither the key nor the section survives the mapping, and some variables have no `Config` field at all: `DEPUTY_SERVER` is read in `internal/cli/cmd/register.go` and `DEPUTY_OSV_BASE_URL` in `internal/analysis/osv/client.go`, by the code that wants them. Give the bindings a representation the loader and the docs can share, then derive the list from that.

## Why this matters, empirically

Auditing the surfaces split them cleanly by whether they derived, if not by outcome. Derived surfaces were faithful to their source. Hand-maintained ones had mostly drifted, offering functions nothing registers, fields that exist on no message, and configuration sections that do not exist. Faithful is not the same as correct, and the difference is the whole point of the next section.

The case that decides the design is the policy entrypoint reference. It **is** generated, and it was still publishing variables that crash the proxy, because the source it derived from was wrong. The same generated file advertises scan helpers that no CEL environment registers (#180). Generation was faithful both times; `helpersByCategory` in `internal/policy/helpers.go` is a hand list, and it was copied accurately.

> Generation propagates correctness and incorrectness equally. Deriving from a wrong root is not better than copying by hand.

So generation is necessary and not sufficient. The root needs a contract test: one that fails when a binding profile declares a variable the runtime cannot supply.

The first version of that test landed in #138, and it is the one part of this that is **guarded**. [`internal/policy/bindings_test.go`](../../internal/policy/bindings_test.go) compares each profile against the names the CEL environment declares, and pins the names that still fail in `undeclaredBindingVars` so the gap is enforced at its current size and cannot grow quietly.

It is not the whole contract, and the test says so itself. The environment is one flat list shared by every entrypoint and every variable in it is `DynType`, so a name it declares may still be unbound at the entrypoint advertising it. Declared is not bound, and the profile can also advertise a name no message carries: `go_artifact_request` offers an optional `licenses` that `GoArtifactRequestPolicyInput` has no field for.

The payload is the real root, and the thing to get right is that **a root is an evaluation route, not an entrypoint**. Filing each profile under one payload kind is the mistake, because a profile can be reached by more than one route with a different payload shape on each.

`scan_report` is the example. It has a typed root through `PolicyHandler.buildActivation` in [`internal/server/policy_handler.go`](../../internal/server/policy_handler.go), which hands `Engine.EvaluateAll` a `*ScanReportPolicyInput`, and a map-backed root in `internal/cli/cmd/scan.go`. Both are live. A guard assuming one payload per profile checks one and leaves the other unguarded.

Routes come in three kinds:

- **Typed proto**, built by a payload builder such as `buildPolicyInput` or `buildPolicyPayload`. The payload can be checked against a descriptor, but a route is the payload *and* the command and entrypoint it evaluates under, and not every route passes them. The package-level convenience `policy.EvaluateAll(ctx, sources, input)` in [`internal/policy/actions.go`](../../internal/policy/actions.go) takes no command or entrypoint and forwards `("", "")` to the method of the same name, and `shouldSkip` applies each filter only when its argument is non-empty. So every caller of the wrapper evaluates with both filters unset, the service interceptor in [`internal/server/server.go`](../../internal/server/server.go) among them: a policy restricted to one entrypoint also runs on every other service procedure. The filter is not overridden, it is never consulted. A descriptor-only guard cannot see this, so a route has to record its filter arguments beside its payload.
- **Map assembled at the call site**, via `EvaluateAllMap`. Not only the CLI: `internal/sandbox/manager.go` is a caller too, so `sandbox_execution` is map-backed and has nothing to do with the CLI. The guard here is two-part: the profile against the descriptor where a typed input exists, plus a test that the assembled map supplies what the descriptor declares.
- **No route at all.** Some profiles have no evaluator anywhere, yet are still published in the generated reference and offered by the MCP tool, so a policy written against one lints clean and never runs (#189). A contract test pointed at every declared profile would go looking for builders that do not exist, which is why knowing which profiles are live is a prerequisite for the guard rather than a detail of it.

The policy tooling sits outside those kinds, and a guard cannot be built on it. `policy simulate` and `policy test` wrap whatever JSON they are handed in a `structpb.Struct` and go through the package-level wrapper, so the payload answers to no profile and no descriptor, and the filters are unset like every other caller of it. A bundle scoped to `oci_artifact_request` still fires against a payload whose `env.entrypoint` is `scan_vulnerability`:

```
$ deputy policy simulate --policy p.yaml --input in.json
Input 0:
  DENY from p.yaml::only-oci: fired despite the entrypoint filter
```

That makes them good for exercising an expression and misleading as a check that a policy will behave the same in production. A route contract belongs at the route, not in the tool an author reaches for.

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

**Rules to design toward.** Every one of them is **direction**, and each names its gap:

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
2. Regenerate every direct projection in the same change: the ConnectRPC and MCP bindings, the pluginrpc ones, and the embedded descriptor set. Skip one and the descriptor guards keep inspecting the previous generation, where they pass. If the change touched a contract something outside this repository speaks, a plugin's or a public service's, run `buf breaking` yourself before it lands; nothing in CI runs buf.
3. Decide the ergonomic affordance deliberately, for the CLI and for the [`sdk`](../../sdk) wrapper if the capability is a new procedure or a new request field, and write the correspondence test with it. Expect to design that test rather than copy one.
4. For the DSL, derive the vocabulary where a canonical set exists to derive from, and edit the LSP by hand where one does not. Policy modes come from `policy.Modes()` and severity names from `policy.SeverityConstantNames()`, so the completions follow. Scopes do not: `internal/policy/evaluator.go` owns `scopeConstants` and `internal/policy/lsp/completions.go` repeats its members, so extending that vocabulary means editing both and adding the correspondence test that would have caught the gap. Apply the admission test before adding a helper.
5. If it crosses the proxy, decide what the extension band says.
6. If it is configurable, add the field to `internal/config.Config`, give it a default wherever its section is defaulted, then edit the matching `*FromEnv` loader if it takes an environment variable, then edit the tables in [`docs/reference/configuration.md`](../reference/configuration.md). Separate edits, none derived from another, until the mechanism in *Choosing a mechanism* is built. Skip the loader and the setting has no environment binding; skip the tables and it is undocumented. Either way nothing fails.
7. Add the contract test at the root, not only at the leaves.

If a capability has to be typed into more than one place, that is the signal something should be derived that is not.

## Choosing a mechanism

- **Runtime protoreflect and the embedded descriptor set** for anything needing proto comments at runtime: MCP descriptions, LSP hovers, generated docs. Note that `protoc-gen-go` strips `SourceCodeInfo`, which is why [`descriptorset.binpb`](../../internal/proto/descriptorset) exists.
- **A Go generator that imports the registry and reads the descriptor set** when the output joins proto data with something only Go knows. Per-entrypoint CEL environment declarations are the strongest candidate: generating them from binding profiles plus descriptors turns unbound variables into compile errors. It has to be a Go generator rather than a protoc plugin, because a plugin receives only descriptors and options, and `BindingProfiles` is a Go map in [`internal/policy/bindings.go`](../../internal/policy/bindings.go). A protoc plugin would have to parse repository Go source to see it, which keeps the second source of truth rather than removing it. `internal/docsgen` already works this way and is the precedent to copy.
- **A custom protoc plugin** only once the metadata it needs lives in proto. Moving entrypoint bindings into proto options would make one possible here, and would be the cleaner end state, but that is a prerequisite rather than a detail.
- **Reflection over the Go struct** for the configuration keys, since that struct is the contract until it moves to proto. It does not render the reference tables as they stand, and scoping it correctly is the point of listing it. The `yaml` and `json` tags name every file key and the field types give the type column, but the other two columns are outside reflection's reach. Defaults live in the `defaultConfig()` composite literal and in further defaulting beside it (`HTTPConfig.WithDefaults`, `otel.DefaultConfig()`), some computed at run time: `defaultCacheDir()` reads `DEPUTY_CACHE_DIR` and otherwise joins the user's home directory, so there is no constant to print. Descriptions live in Go doc comments on the fields, which the compiler discards. Reflection alone therefore renders a table with two columns missing, or gets them from a second hand-maintained source beside the struct, which is the drift the rule exists to remove. Two ways out that avoid that: model the missing metadata on the struct so reflection sees it, as `default` and `doc` tags that the defaulting functions read too so one answer serves both, or make it a source-aware generator that parses `internal/config` for the literals and comments the way it would read any other Go-only source. Absent either, scope reflection to a key-correspondence check, every documented key has a field and every field a documented key, which is the drift that produced a documented `sbom` section with nothing behind it.
- **Not reflection for the `DEPUTY_*` list.** Reflection sees the tags, and the tags do not encode the environment contract, so it cannot recover a variable's name, its parser, or whether the field has an environment binding at all. That list needs the binding modeled first, as an `env` tag or a registry the loader reads, and then it derives from the same mechanism. If configuration ever moves into proto, all of this becomes an ordinary direct projection and the mechanism above applies instead.
- **Neither** for the ergonomic layer. Generate the contract, hand-write the affordance, and let a drift test hold the edge.
