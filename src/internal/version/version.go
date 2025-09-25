// FILE: logwisp/src/internal/version/version.go
package version

import "fmt"

var (
	// Version is set at compile time via -ldflags
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

// Returns a formatted version string
func String() string {
	if Version == "dev" {
		return fmt.Sprintf("dev (commit: %s, built: %s)", GitCommit, BuildTime)
	}
	return fmt.Sprintf("%s (commit: %s, built: %s)", Version, GitCommit, BuildTime)
}

// Returns just the version tag
func Short() string {
	return Version
}