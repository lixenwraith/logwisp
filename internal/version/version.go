package version

import (
	"fmt"
	"runtime/debug"
)

var (
	// Version is the application version, set at compile time via -ldflags
	Version = "dev"
	// GitCommit is the git commit hash, set at compile time
	GitCommit = "unknown"
	// BuildTime is the application build time, set at compile time
	BuildTime = "unknown"
)

// init fills what -ldflags left unset from the build info: `go install
// module@version` stamps the module version, a build in a checkout the commit.
func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if v := info.Main.Version; Version == "dev" && v != "" && v != "(devel)" {
		Version = v
	}
	for _, s := range info.Settings {
		switch {
		case s.Key == "vcs.revision" && GitCommit == "unknown":
			GitCommit = s.Value[:min(len(s.Value), 12)]
		case s.Key == "vcs.time" && BuildTime == "unknown":
			BuildTime = s.Value
		}
	}
}

// String returns a detailed, formatted version string including commit and build time
func String() string {
	return fmt.Sprintf("%s (commit: %s, built: %s)", Version, GitCommit, BuildTime)
}

// Short returns just the version tag
func Short() string {
	return Version
}
