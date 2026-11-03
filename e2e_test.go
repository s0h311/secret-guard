package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildBinary compiles the CLI once per test binary run and returns its path.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "secret-guard")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// runCLI invokes the binary with stdin and returns stdout and the exit code.
func runCLI(t *testing.T, bin, stdin string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return stdout.String(), stderr.String(), code
}

const dirtyPatch = `diff --git a/app/config.go b/app/config.go
--- a/app/config.go
+++ b/app/config.go
@@ -5,2 +5,4 @@
 const (
+	awsKey = "AKIAIOSFODNN7EXAMPLE"
+	dbPass = "pr0dpassw0rd!"
 )
`

const cleanPatch = `diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1,2 +1,3 @@
 # Title
+Some ordinary prose with no credentials in it.
 
`

func TestCLIFindsSecretsInAPatchOnStdin(t *testing.T) {
	bin := buildBinary(t)

	stdout, _, code := runCLI(t, bin, dirtyPatch, "--diff", "-")
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (findings)", code)
	}
	if !strings.Contains(stdout, "app/config.go:6") {
		t.Errorf("want a finding at app/config.go:6, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "app/config.go:7") {
		t.Errorf("want a finding at app/config.go:7, got:\n%s", stdout)
	}
	if strings.Contains(stdout, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("output leaked the full secret:\n%s", stdout)
	}
}

func TestCLIIsSilentAndSucceedsOnACleanPatch(t *testing.T) {
	bin := buildBinary(t)

	stdout, _, code := runCLI(t, bin, cleanPatch, "--diff", "-")
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (clean), output:\n%s", code, stdout)
	}
}

func TestCLIJSONShape(t *testing.T) {
	bin := buildBinary(t)

	stdout, _, code := runCLI(t, bin, dirtyPatch, "--diff", "-", "--json")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}

	var doc struct {
		Count    int `json:"count"`
		Findings []struct {
			Path   string `json:"path"`
			Line   int    `json:"line"`
			Rule   string `json:"rule"`
			Tier   int    `json:"tier"`
			Reason string `json:"reason"`
			Masked string `json:"masked"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout)
	}
	if doc.Count != len(doc.Findings) || doc.Count != 2 {
		t.Fatalf("count = %d with %d findings, want 2 of each", doc.Count, len(doc.Findings))
	}
	f := doc.Findings[0]
	if f.Path != "app/config.go" || f.Line != 6 || f.Rule != "aws-access-key-id" || f.Tier != 1 {
		t.Errorf("first finding = %+v, want app/config.go:6 aws-access-key-id tier 1", f)
	}
	if f.Reason == "" || f.Masked == "" {
		t.Errorf("finding is missing reason or masked value: %+v", f)
	}
}

// A usage error must be distinguishable from findings, so CI can tell "the
// tool broke" apart from "the tool found something".
func TestCLIUsageErrorExitsTwo(t *testing.T) {
	bin := buildBinary(t)

	if _, _, code := runCLI(t, bin, "", "--nope"); code != 2 {
		t.Errorf("exit code = %d, want 2 for an unknown flag", code)
	}
	if _, _, code := runCLI(t, bin, "", "--diff", "/nonexistent.patch"); code != 2 {
		t.Errorf("exit code = %d, want 2 for a missing patch file", code)
	}
}

// The hooks must actually fire inside a real repository, and the pre-commit
// hook must block a commit that carries a secret.
func TestHookInstallBlocksACommitWithASecret(t *testing.T) {
	bin := buildBinary(t)
	repo := t.TempDir()

	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	if out, err := git("init", "-q"); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}

	install := exec.Command(bin, "hook", "install")
	install.Dir = repo
	if out, err := install.CombinedOutput(); err != nil {
		t.Fatalf("hook install: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "hooks", "pre-commit")); err != nil {
		t.Fatalf("pre-commit hook was not written: %v", err)
	}

	if err := os.WriteFile(filepath.Join(repo, "creds.yml"), []byte("api_key: \"AKIAIOSFODNN7EXAMPLE\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := git("add", "creds.yml"); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}

	out, err := git("commit", "-m", "add creds")
	if err == nil {
		t.Fatalf("commit succeeded but should have been blocked:\n%s", out)
	}
	if !strings.Contains(out, "aws-access-key-id") {
		t.Errorf("hook output does not name the rule:\n%s", out)
	}

	// The documented bypass must work, otherwise the tool is a trap.
	if out, err := git("commit", "--no-verify", "-m", "add creds"); err != nil {
		t.Fatalf("--no-verify commit should succeed: %v\n%s", err, out)
	}
}

// Regression: for a branch the remote has never seen there is no remote SHA to
// diff against. An earlier version fell back to the local main/master, whose
// merge base with itself is its own tip, so the scan silently examined nothing
// and the push went through with secrets in it.
func TestPrePushHookBlocksANewBranchCarryingASecret(t *testing.T) {
	bin := buildBinary(t)
	root := t.TempDir()
	repo := filepath.Join(root, "work")
	remote := filepath.Join(root, "remote.git")

	gitIn := func(dir string, args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	if out, err := gitIn(root, "init", "-q", "--bare", remote); err != nil {
		t.Fatalf("init bare: %v\n%s", err, out)
	}
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := gitIn(repo, "init", "-q", "-b", "main"); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}

	// Commit the secret BEFORE the hooks exist, which is what makes this a
	// pre-push concern rather than a pre-commit one.
	if err := os.WriteFile(filepath.Join(repo, "deploy.sh"),
		[]byte("#!/bin/sh\nexport AWS_KEY=\"AKIAIOSFODNN7EXAMPLE\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := gitIn(repo, "add", "-A"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if out, err := gitIn(repo, "commit", "-qm", "deploy script"); err != nil {
		t.Fatalf("commit: %v\n%s", err, out)
	}

	install := exec.Command(bin, "hook", "install")
	install.Dir = repo
	if out, err := install.CombinedOutput(); err != nil {
		t.Fatalf("hook install: %v\n%s", err, out)
	}
	if out, err := gitIn(repo, "remote", "add", "origin", remote); err != nil {
		t.Fatalf("remote add: %v\n%s", err, out)
	}

	out, err := gitIn(repo, "push", "-u", "origin", "main")
	if err == nil {
		t.Fatalf("push succeeded but should have been blocked:\n%s", out)
	}
	if !strings.Contains(out, "aws-access-key-id") {
		t.Errorf("push output does not name the offending rule:\n%s", out)
	}

	// And the bypass must still let it through.
	if out, err := gitIn(repo, "push", "--no-verify", "-u", "origin", "main"); err != nil {
		t.Fatalf("--no-verify push should succeed: %v\n%s", err, out)
	}
}

// Regression: `git ls-files --others` is scoped to the current directory and
// prints CWD-relative paths, while `git diff` is repo-wide with root-relative
// ones. An earlier version joined the former onto the repo root, so running
// the scan from a subdirectory silently found no untracked files at all.
func TestScanFromSubdirectoryStillSeesUntrackedFiles(t *testing.T) {
	bin := buildBinary(t)
	repo := t.TempDir()

	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	if out, err := git("init", "-q"); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := git("add", "-A"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if out, err := git("commit", "-qm", "init"); err != nil {
		t.Fatalf("commit: %v\n%s", err, out)
	}

	nested := filepath.Join(repo, "services", "api")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, ".env"),
		[]byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "--json")
	cmd.Dir = nested // run from the subdirectory, not the repo root
	cmd.Stdin = strings.NewReader("")
	out, _ := cmd.Output()

	var doc struct {
		Count    int `json:"count"`
		Findings []struct {
			Path string `json:"path"`
			Rule string `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if doc.Count == 0 {
		t.Fatalf("found nothing when run from a subdirectory; want the untracked .env")
	}
	// Paths must be repo-root-relative so they are clickable from anywhere.
	for _, f := range doc.Findings {
		if !strings.HasPrefix(f.Path, "services/api/.env") {
			t.Errorf("path %q is not repo-root-relative", f.Path)
		}
	}
}

// testRepo creates an initialised repo and returns a git runner for it.
func testRepo(t *testing.T) (string, func(args ...string) (string, error)) {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := git("init", "-q", "-b", "main"); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	return dir, git
}

// Regression: `git diff a..b` compares trees, so a secret added in one commit
// and deleted in a later one nets out to nothing — while both commits are
// still being pushed and the secret stays recoverable in the remote's history.
// The pushed range must be walked commit by commit.
func TestPrePushSeesASecretAddedThenDeletedWithinTheRange(t *testing.T) {
	bin := buildBinary(t)
	repo, git := testRepo(t)
	remote := filepath.Join(t.TempDir(), "remote.git")

	if out, err := exec.Command("git", "init", "-q", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("init bare: %v\n%s", err, out)
	}

	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(msg string) {
		if out, err := git("add", "-A"); err != nil {
			t.Fatalf("add: %v\n%s", err, out)
		}
		if out, err := git("commit", "--no-verify", "-qm", msg); err != nil {
			t.Fatalf("commit %s: %v\n%s", msg, err, out)
		}
	}

	write("base.txt", "base\n")
	commit("base")
	write("leak.txt", "AWS=AKIAIOSFODNN7EXAMPLE\n")
	commit("add leak")
	if out, err := git("rm", "-q", "leak.txt"); err != nil {
		t.Fatalf("rm: %v\n%s", err, out)
	}
	commit("remove leak")

	// Sanity check that this is actually the hard case: the endpoint diff is
	// empty, so only a per-commit walk can see the secret.
	if out, err := git("diff", "HEAD~2..HEAD", "--name-only"); err != nil || strings.TrimSpace(out) != "" {
		t.Fatalf("expected an empty endpoint diff, got %q (err %v)", out, err)
	}

	install := exec.Command(bin, "hook", "install")
	install.Dir = repo
	if out, err := install.CombinedOutput(); err != nil {
		t.Fatalf("hook install: %v\n%s", err, out)
	}
	if out, err := git("remote", "add", "origin", remote); err != nil {
		t.Fatalf("remote add: %v\n%s", err, out)
	}

	out, err := git("push", "-u", "origin", "main")
	if err == nil {
		t.Fatalf("push succeeded but the range contains a secret:\n%s", out)
	}
	if !strings.Contains(out, "aws-access-key-id") {
		t.Errorf("push output does not name the rule:\n%s", out)
	}
}

// Regression: a repo with no HEAD yet is the highest-risk moment — `git init`
// followed by `git add .` of a tree containing a .env. An earlier version
// skipped the tracked diff entirely when HEAD did not resolve, and `ls-files
// --others` does not list staged files, so the scan reported clean.
func TestWorkingTreeScanWorksBeforeTheFirstCommit(t *testing.T) {
	bin := buildBinary(t)
	repo, git := testRepo(t)

	if err := os.WriteFile(filepath.Join(repo, ".env"),
		[]byte("DB_PASSWORD=supersecretpassword\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := git("add", "-A"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}

	cmd := exec.Command(bin, "--json")
	cmd.Dir = repo
	cmd.Stdin = strings.NewReader("")
	out, _ := cmd.Output()

	var doc struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if doc.Count == 0 {
		t.Error("found nothing in a repo with no HEAD; want the staged .env")
	}
}
