package diff

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Source describes where a diff should come from.
type Source struct {
	// Repo is the working directory git runs in.
	Repo string
	// Base and Head are refs. When Base is empty the working tree is compared
	// against HEAD.
	Base string
	Head string
	// Staged compares the index against HEAD instead of the working tree.
	Staged bool
	// Context is the number of context lines. More context makes `near`
	// constraints more accurate at the cost of a larger diff.
	Context int
}

// ErrGitMissing is returned when git is not on PATH.
var ErrGitMissing = errors.New("git not found on PATH; pass a patch with --diff instead")

// FromGit shells out to git and parses the result.
func FromGit(s Source) (*Diff, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, ErrGitMissing
	}
	ctx := s.Context
	if ctx <= 0 {
		ctx = 5
	}

	args := []string{
		"-C", repoOrDot(s.Repo),
		"--no-pager",
		"diff",
		"--no-color",
		"--no-ext-diff",
		"--find-renames",
		fmt.Sprintf("-U%d", ctx),
	}
	switch {
	case s.Staged:
		args = append(args, "--cached")
		if s.Base != "" {
			args = append(args, s.Base)
		}
	case s.Base != "" && s.Head != "":
		// Three-dot: compare head against the merge base, which is what a pull
		// request actually shows. Two-dot would also report changes that landed
		// on the base branch since the fork point.
		args = append(args, s.Base+"..."+s.Head)
	case s.Base != "":
		args = append(args, s.Base+"...HEAD")
	default:
		// Working tree against HEAD.
	}

	out, err := run(args...)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out) == "" {
		return &Diff{}, nil
	}
	return ParseString(out)
}

// ResolveBase picks a sensible base ref when the user did not name one. It
// prefers the CI-provided base branch, then the repository's default branch,
// then the previous commit - in that order, because that is the order of
// decreasing certainty about what "the change" means.
func ResolveBase(repo string) string {
	for _, env := range []string{"GITHUB_BASE_REF", "CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "CHANGE_TARGET"} {
		if v := os.Getenv(env); v != "" {
			for _, cand := range []string{"origin/" + v, v} {
				if refExists(repo, cand) {
					return cand
				}
			}
		}
	}
	if out, err := run("-C", repoOrDot(repo), "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"); err == nil {
		ref := strings.TrimSpace(out)
		if ref != "" {
			return strings.TrimPrefix(ref, "refs/remotes/")
		}
	}
	for _, cand := range []string{"origin/main", "origin/master", "main", "master"} {
		if refExists(repo, cand) {
			return cand
		}
	}
	if refExists(repo, "HEAD~1") {
		return "HEAD~1"
	}
	return ""
}

// RepoRoot returns the top level of the repository containing dir.
func RepoRoot(dir string) (string, error) {
	out, err := run("-C", repoOrDot(dir), "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// Describe returns a short identifier for a ref, for report metadata.
func Describe(repo, ref string) string {
	if ref == "" {
		ref = "HEAD"
	}
	out, err := run("-C", repoOrDot(repo), "rev-parse", "--short", ref)
	if err != nil {
		return ref
	}
	return ref + "@" + strings.TrimSpace(out)
}

func refExists(repo, ref string) bool {
	_, err := run("-C", repoOrDot(repo), "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	return err == nil
}

func repoOrDot(p string) string {
	if p == "" {
		return "."
	}
	return p
}

func run(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}
