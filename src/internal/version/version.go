// FILE: logwisp/src/internal/version/version.go
package version

import "fmt"

var (
	// Version is the application version, set at compile time via -ldflags.
	Version = "dev"
	// GitCommit is the git commit hash, set at compile time.
	GitCommit = "unknown"
	// BuildTime is the application build time, set at compile time.
	BuildTime = "unknown"
)

// String returns a detailed, formatted version string including commit and build time.
func String() string {
	if Version == "dev" {
		return fmt.Sprintf("dev (commit: %s, built: %s)", GitCommit, BuildTime)
	}
	return fmt.Sprintf("%s (commit: %s, built: %s)", Version, GitCommit, BuildTime)
}

// Short returns just the version tag.
func Short() string {
	return Version
}