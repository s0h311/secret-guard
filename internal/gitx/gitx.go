// Package gitx turns the various "what changed?" questions into unified diffs.
package gitx

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/s0h311/secret-guard/internal/diff"
)

// ZeroSHA is what git passes for a ref that does not exist yet (a new branch)
// or is being deleted.
const ZeroSHA = "0000000000000000000000000000000000000000"

// MaxPushCommits caps how much history a single pre-push scan will read. Past
// this the scan is skipped with a warning rather than stalling a push for
// minutes, which is how users learn to reach for --no-verify permanently.
const MaxPushCommits = 1000

func run(args ...string) ([]byte, error) {
	return runIn("", args...)
}

// runIn runs git with an explicit working directory. Needed because some git
// commands are scoped to the current directory rather than the whole repo.
func runIn(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// InRepo reports whether the working directory is inside a git work tree.
func InRepo() bool {
	_, err := run("rev-parse", "--git-dir")
	return err == nil
}

// WorkingTree returns everything not yet committed: tracked modifications
// against HEAD, plus untracked files rendered as whole-file additions.
//
// Untracked files matter more than tracked edits here - a freshly created
// .env is the most common real leak, and `git diff` cannot see it at all.
func WorkingTree() ([]diff.File, error) {
	var files []diff.File

	// A repo with no HEAD still has content worth scanning: `git init` then
	// `git add .` is exactly when a .env gets staged. Diff against the empty
	// tree so that content is seen, rather than skipping the diff entirely -
	// `ls-files --others` would not catch it either, since it is now indexed.
	base := "HEAD"
	if _, err := run("rev-parse", "--verify", "HEAD"); err != nil {
		base = EmptyTree
	}
	out, err := run("diff", "--no-color", "--no-ext-diff", base)
	if err != nil {
		return nil, err
	}
	fs, err := diff.Parse(bytes.NewReader(out))
	if err != nil {
		return nil, err
	}
	files = append(files, fs...)

	root, rerr := run("rev-parse", "--show-toplevel")
	if rerr != nil {
		return nil, rerr
	}
	topLevel := strings.TrimSpace(string(root))

	// `ls-files --others` is scoped to the current directory and prints paths
	// relative to it, unlike `git diff`, which is repo-wide with root-relative
	// paths. Run it from the top level so a scan started in a subdirectory
	// still sees every untracked file, and so the paths line up.
	untracked, err := runIn(topLevel, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}

	for _, name := range strings.Split(string(untracked), "\x00") {
		if name == "" {
			continue
		}
		f, err := syntheticFile(filepath.Join(topLevel, name), name)
		if err != nil {
			// An unreadable or vanished file is not worth failing the scan.
			continue
		}
		files = append(files, f)
	}
	return files, nil
}

func syntheticFile(abs, name string) (diff.File, error) {
	info, err := os.Stat(abs)
	if err != nil || info.IsDir() {
		return diff.File{}, errors.New("not a readable file")
	}
	// Large untracked files are almost never hand-written config.
	if info.Size() > 2<<20 {
		return diff.File{}, errors.New("too large")
	}
	fh, err := os.Open(abs)
	if err != nil {
		return diff.File{}, err
	}
	defer fh.Close()
	return diff.Synthetic(name, fh)
}

// Staged returns the diff of the index against HEAD - what a commit would
// contain. This is what the pre-commit hook scans.
func Staged() ([]diff.File, error) {
	args := []string{"diff", "--no-color", "--no-ext-diff", "--cached"}
	if _, err := run("rev-parse", "--verify", "HEAD"); err != nil {
		// No HEAD yet: compare against the empty tree so the first commit is
		// still scanned.
		args = append(args, EmptyTree)
	}
	out, err := run(args...)
	if err != nil {
		return nil, err
	}
	return diff.Parse(bytes.NewReader(out))
}

// Commit returns the diff introduced by a single commit.
//
// --cc is required for merge commits: without it `diff-tree -p` prints nothing
// at all for a merge, so a secret added while resolving a conflict would be
// reported as "no secrets found". For a non-merge it changes nothing.
func Commit(rev string) ([]diff.File, error) {
	out, err := run("diff-tree", "-p", "--cc", "--no-commit-id", "--root", "--no-color", rev)
	if err != nil {
		return nil, err
	}
	return diff.Parse(bytes.NewReader(out))
}

// Range returns the added lines of every commit in from..to.
//
// It walks the commits rather than diffing the two endpoints. `git diff a..b`
// compares trees, so a secret added in one commit and deleted in a later one
// nets out to nothing - while both commits are still being pushed, and the
// secret stays recoverable in the remote's history forever. Walking commits is
// the only way to see it.
//
// --format= suppresses commit messages, which would otherwise be parsed as
// content (a message line starting with "+" would look like an added line).
// --cc includes merge commits, which `log -p` omits by default.
func Range(from, to string) ([]diff.File, error) {
	out, err := run("log", "-p", "--cc", "--format=", "--no-color", "--no-ext-diff", from+".."+to)
	if err != nil {
		return nil, err
	}
	return diff.Parse(bytes.NewReader(out))
}

// CountCommits returns how many commits are in from..to.
func CountCommits(from, to string) (int, error) {
	out, err := run("rev-list", "--count", from+".."+to)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

// EmptyTree is git's canonical empty tree object, used as the base when the
// commits being pushed go all the way back to a root commit.
const EmptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// ErrNothingNew means every commit on the ref is already present on some
// remote, so a push adds nothing that needs scanning.
var ErrNothingNew = errors.New("no commits that are not already on a remote")

// BaseForNewBranch finds what to diff against for a ref the remote has never
// seen, and reports how many commits are being added.
//
// It asks git for the commits reachable from local but not from ANY remote
// tracking ref. That is exactly "what this push would newly publish", and it
// avoids the trap of falling back to a local main/master: the merge base of a
// branch with itself is its own tip, which would silently scan nothing.
func BaseForNewBranch(localSHA string) (base string, count int, err error) {
	out, err := run("rev-list", localSHA, "--not", "--remotes")
	if err != nil {
		return "", 0, err
	}
	var revs []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			revs = append(revs, l)
		}
	}
	if len(revs) == 0 {
		return "", 0, ErrNothingNew
	}

	// rev-list is newest-first, so the last entry is the oldest new commit.
	oldest := revs[len(revs)-1]
	parent, perr := run("rev-parse", "--verify", oldest+"^")
	if perr != nil {
		// A root commit has no parent; diff against the empty tree so the
		// very first commit of a repository is still scanned.
		return EmptyTree, len(revs), nil
	}
	return strings.TrimSpace(string(parent)), len(revs), nil
}
