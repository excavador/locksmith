// Package gen is the parent of all generated protobuf and ConnectRPC code
// for gpgsmith. It exists only to anchor the //go:generate directive that
// regenerates everything from the .proto sources in proto/gpgsmith/v1/.
//
// To regenerate the wire schema after editing a .proto file:
//
//	just generate          # preferred
//	go generate ./pkg/gen  # equivalent
//
// Both forms invoke buf with cwd set to this directory (pkg/gen). The
// `out: .` setting in proto/buf.gen.yaml is interpreted relative to that
// cwd, so generated files land under pkg/gen/gpgsmith/v1/.... Do NOT
// invoke `buf generate` from any other directory — the relative paths
// will not resolve correctly.
//
// The buf invocation reads proto/buf.gen.yaml, fetches the protoc-gen-go
// and protoc-gen-connect-go plugins from the Buf Schema Registry on first
// run (cached locally afterwards), and writes the generated Go files into
// pkg/gen/gpgsmith/v1/ and pkg/gen/gpgsmith/v1/gpgsmithv1connect/.
//
// Generated files are committed to git so:
//
//   - `go install github.com/excavador/locksmith/cmd/gpgsmith@latest`
//     works without buf installed
//   - CI does not need buf as a build dependency
//   - New contributors can hack on Go code without setting up the proto
//     toolchain (only schema editors need buf, via devbox.json)
package gen

//go:generate buf generate --template ../../proto/buf.gen.yaml ../../proto
