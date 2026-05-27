module github.com/temporalio/deputy

go 1.26.3

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.10-20260415201107-50325440f8f2.1
	buf.build/go/protovalidate v1.1.0
	connectrpc.com/authn v0.2.0
	connectrpc.com/connect v1.19.2
	connectrpc.com/cors v0.1.0
	connectrpc.com/otelconnect v0.9.0
	connectrpc.com/validate v0.6.0
	deps.dev/api/v3 v3.0.0-20250903005441-604c45d5b44b
	github.com/BurntSushi/toml v1.6.0
	github.com/CycloneDX/cyclonedx-go v0.11.0
	github.com/alecthomas/chroma/v2 v2.25.0
	github.com/charmbracelet/fang v1.0.0
	github.com/charmbracelet/glamour v1.0.0
	github.com/charmbracelet/lipgloss v1.1.1-0.20250404203927-76690c660834
	github.com/go-git/go-billy/v5 v5.9.0
	github.com/go-git/go-git/v5 v5.19.1
	github.com/goccy/go-yaml v1.19.2
	github.com/google/cel-go v0.28.1
	github.com/google/go-cmp v0.7.0
	github.com/google/go-github/v63 v63.0.0
	github.com/google/licensecheck v0.3.1
	github.com/google/osv-scalibr v0.3.4
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-retryablehttp v0.7.8
	github.com/lima-vm/go-qcow2reader v0.7.1
	github.com/masahiro331/go-disk v0.0.0-20260423015231-f7a470ebd472
	github.com/masahiro331/go-ext4-filesystem v0.0.0-20260423010602-fe51f5b5e52b
	github.com/modelcontextprotocol/go-sdk v1.6.1
	github.com/ossf/osv-schema/bindings/go v0.0.0-20250902063920-695987a6b7da
	github.com/package-url/packageurl-go v0.1.6
	github.com/pandatix/go-cvss v0.6.2
	github.com/picatz/jose v0.0.0-20250816152409-7521c7f65f1b
	github.com/picatz/openai v0.0.0-20251126013453-02ace0a229c7
	github.com/pjbgf/sha1cd v0.6.0
	github.com/protobom/protobom v0.5.4
	github.com/sourcegraph/go-lsp v0.0.0-20240223163137-f80c5dd31dfd
	github.com/sourcegraph/jsonrpc2 v0.2.1
	github.com/spdx/tools-golang v0.5.7
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/ulikunitz/xz v0.5.15
	go.opentelemetry.io/contrib/bridges/otelslog v0.18.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.68.0
	go.opentelemetry.io/otel v1.43.0
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc v0.15.0
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp v0.15.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.39.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.39.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.39.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.39.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.39.0
	go.opentelemetry.io/otel/log v0.19.0
	go.opentelemetry.io/otel/metric v1.43.0
	go.opentelemetry.io/otel/sdk v1.43.0
	go.opentelemetry.io/otel/sdk/log v0.19.0
	go.opentelemetry.io/otel/sdk/metric v1.43.0
	go.opentelemetry.io/otel/trace v1.43.0
	golang.org/x/mod v0.36.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sync v0.20.0
	golang.org/x/term v0.43.0
	golang.org/x/time v0.15.0
	google.golang.org/genproto/googleapis/api v0.0.0-20251202230838-ff82c1b0f217
	google.golang.org/grpc v1.80.0-dev
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
	osv.dev/bindings/go v0.0.0-20250808040635-c189436f8791
	pluginrpc.com/pluginrpc v0.5.0
)

require (
	buf.build/gen/go/pluginrpc/pluginrpc/protocolbuffers/go v1.36.10-20241007202033-cf42259fcbfc.1 // indirect
	charm.land/lipgloss/v2 v2.0.3 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cyphar.com/go-pathrs v0.2.1 // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20240806141605-e8a1dd7889d6 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20230306123547-8075edf89bb0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20250102033503-faa5f7b0171c // indirect
	github.com/Microsoft/hcsshim v0.14.1 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/ayoubfaouzi/pkcs7 v0.2.3 // indirect
	github.com/charmbracelet/ultraviolet v0.0.0-20260525132238-948f4557a654 // indirect
	github.com/charmbracelet/x/exp/slice v0.0.0-20260527151214-009e6338d40d // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/charmbracelet/x/windows v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/containerd/cgroups/v3 v3.1.3 // indirect
	github.com/containerd/containerd v1.7.23 // indirect
	github.com/containerd/containerd/api v1.10.0 // indirect
	github.com/containerd/continuity v0.4.5 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v1.0.0-rc.2 // indirect
	github.com/containerd/ttrpc v1.2.8 // indirect
	github.com/dlclark/regexp2/v2 v2.1.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/gorilla/css v1.0.1 // indirect
	github.com/lunixbochs/struc v0.0.0-20241101090106-8d528fa2c543 // indirect
	github.com/microcosm-cc/bluemonday v1.0.27 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/moby/api v1.54.2 // indirect
	github.com/moby/moby/client v0.4.1 // indirect
	github.com/moby/sys/atomicwriter v0.1.0 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/signal v0.7.1 // indirect
	github.com/moby/sys/user v0.4.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/morikuni/aec v1.1.0 // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/opencontainers/runtime-spec v1.3.0 // indirect
	github.com/opencontainers/selinux v1.13.1 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/tink-crypto/tink-go/v2 v2.6.0 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	github.com/yuin/goldmark v1.8.2 // indirect
	github.com/yuin/goldmark-emoji v1.0.6 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	google.golang.org/genproto v0.0.0-20250603155806-513f23925822 // indirect
)

require (
	cel.dev/expr v0.25.2 // indirect
	dario.cat/mergo v1.0.2 // indirect
	deps.dev/api/v3alpha v0.0.0-20250903005441-604c45d5b44b // indirect
	deps.dev/util/maven v0.0.0-20260422013440-90c27f84dd6f // indirect
	deps.dev/util/pypi v0.0.0-20260422013440-90c27f84dd6f // indirect
	deps.dev/util/resolve v0.0.0-20250903005441-604c45d5b44b // indirect
	deps.dev/util/semver v0.0.0-20260422013440-90c27f84dd6f // indirect
	github.com/GehirnInc/crypt v0.0.0-20230320061759-8cc1b52080c5 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.4.1 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/anchore/go-struct-converter v0.1.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/x/ansi v0.11.7 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/exp/charmtone v0.0.0-20260527151214-009e6338d40d // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/common-nighthawk/go-figure v0.0.0-20210622060536-734e95fb86be // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/typeurl/v2 v2.2.3 // indirect
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/deitch/magic v0.0.0-20240306090643-c67ab88f10cb // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/cli v29.5.2+incompatible // indirect
	github.com/docker/docker v28.5.2+incompatible
	github.com/docker/docker-credential-helpers v0.9.7 // indirect
	github.com/docker/go-connections v0.7.0
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/edsrzf/mmap-go v1.2.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/erikvarga/go-rpmdb v0.0.0-20250523120114-a15a62cd4593 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/go-containerregistry v0.21.6
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/google/uuid v1.6.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.6.0 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/mattn/go-runewidth v0.0.23 // indirect
	github.com/micromdm/plist v0.2.2 // indirect
	github.com/moby/buildkit v0.26.3
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/mango v0.2.0 // indirect
	github.com/muesli/mango-cobra v1.3.0 // indirect
	github.com/muesli/mango-pflag v0.2.0 // indirect
	github.com/muesli/roff v0.1.0 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/olekukonko/cat v0.0.0-20250911104152-50322a0618f6 // indirect
	github.com/olekukonko/errors v1.3.0 // indirect
	github.com/olekukonko/ll v0.1.8 // indirect
	github.com/olekukonko/tablewriter v1.1.4 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rust-secure-code/go-rustaudit v0.0.0-20250226111315-e20ec32e963c // indirect
	github.com/saferwall/pe v1.6.5 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/skeema/knownhosts v1.3.2 // indirect
	github.com/spdx/gordf v0.0.0-20250128162952-000978ccd6fb // indirect
	github.com/tidwall/gjson v1.19.0 // indirect
	github.com/tidwall/jsonc v0.3.3 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tklauser/go-sysconf v0.4.0 // indirect
	github.com/tklauser/numcpus v0.12.0 // indirect
	github.com/tonistiigi/go-csvvalue v0.0.0-20240814133006-030d3b2625d0 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.etcd.io/bbolt v1.4.3 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/proto/otlp v1.9.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/exp v0.0.0-20260527015227-08cc5374adb3 // indirect
	golang.org/x/net v0.55.0
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/telemetry v0.0.0-20260527142108-59979362b252 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/tools v0.45.0 // indirect
	golang.org/x/vuln v1.3.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	gopkg.in/ini.v1 v1.67.2 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	modernc.org/libc v1.72.5 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.50.1 // indirect
	sigs.k8s.io/release-utils v0.12.4 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
	www.velocidex.com/golang/regparser v0.0.0-20250203141505-31e704a67ef7 // indirect
)
