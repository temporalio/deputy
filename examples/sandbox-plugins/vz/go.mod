module github.com/picatz/deputy/examples/sandbox-plugins/vz

go 1.25.5

require (
	connectrpc.com/connect v1.19.1
	github.com/Code-Hex/vz/v3 v3.3.0
	github.com/creack/pty v1.1.24
	github.com/picatz/deputy v0.0.0
	golang.org/x/net v0.47.0
	golang.org/x/sys v0.40.0
	golang.org/x/term v0.39.0
	google.golang.org/protobuf v1.36.10
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.10-20251209175733-2a1774d88802.1 // indirect
	github.com/Code-Hex/go-infinity-channel v1.0.0 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/text v0.32.0 // indirect
)

replace github.com/picatz/deputy => ../../..
