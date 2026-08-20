// Package version exposes build metadata, injected at link time.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// These are overridden with -ldflags at release time. See the Makefile.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// Short returns just the semantic version.
func Short() string { return Version }

// Full returns a human readable, single-line build banner.
func Full() string {
	commit := Commit
	if commit == "" {
		commit = vcsRevision()
	}
	if commit == "" {
		commit = "unknown"
	}
	if len(commit) > 12 {
		commit = commit[:12]
	}
	date := Date
	if date == "" {
		date = "unknown"
	}
	return fmt.Sprintf("threatdiff %s (commit %s, built %s, %s/%s, %s)",
		Version, commit, date, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func vcsRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return ""
}
