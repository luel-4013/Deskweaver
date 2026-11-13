// Package version holds build metadata injected at link time.
package version

import "runtime"

var (
	// Version is the release version.
	Version = "0.1.0-dev"
	// Commit is the source revision.
	Commit = "unknown"
	// BuildDate is the UTC build timestamp.
	BuildDate = "unknown"
)

// String returns a one-line version string.
func String() string {
	return Version + " (" + Commit + ", " + BuildDate + ", " + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
