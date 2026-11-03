// Package hook installs and removes the git hooks that run secret-guard.
//
// Two hooks are installed together because they catch different failures:
// pre-commit stops a secret while the fix is still cheap (unstage the line),
// and pre-push is the last check before it leaves the machine, covering
// commits that arrived by rebase, merge, amend, or from another machine.
package hook

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Names are the hooks managed by this tool.
var Names = []string{"pre-commit", "pre-push"}

// marker identifies scripts this tool wrote, so uninstall never deletes a
// hook that belongs to someone else.
const marker = "# managed-by: secret-guard"

// chainedSuffix is appended to a pre-existing hook we move aside, so it can
// still be invoked.
const chainedSuffix = ".secret-guard-chained"

type Result struct {
	Installed []string
	Chained   []string
	HooksPath string
	Global    bool
	// ClearedConfig reports whether uninstall also unset core.hooksPath.
	ClearedConfig bool
}

// Install writes both hooks. Global mode points git's core.hooksPath at a
// shared directory; otherwise the hooks go in this repo's own hooks dir.
// A non-empty override installs into that directory instead, which is how a
// user adopts a hooks dir they already have.
func Install(global bool, override string) (Result, error) {
	res := Result{Global: global}

	dir, err := targetDir(global, override)
	if err != nil {
		return res, err
	}
	res.HooksPath = dir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return res, err
	}

	if global {
		existing, _ := gitConfig("--global", "core.hooksPath")
		if existing != "" && filepath.Clean(existing) != filepath.Clean(dir) {
			return res, fmt.Errorf(
				"git already has a global core.hooksPath set to %q.\n"+
					"Refusing to repoint it, since that would silently disable those hooks.\n"+
					"Either install the hooks there yourself, or run:\n"+
					"  secret-guard hook install --global --hooks-path %s",
				existing, existing)
		}
	}

	self, err := selfPath()
	if err != nil {
		return res, err
	}

	for _, name := range Names {
		path := filepath.Join(dir, name)
		chained, err := preserveExisting(path)
		if err != nil {
			return res, err
		}
		if chained {
			res.Chained = append(res.Chained, name)
		}
		if err := os.WriteFile(path, script(name, self, chained), 0o755); err != nil {
			return res, err
		}
		res.Installed = append(res.Installed, path)
	}

	if global {
		if err := setGitConfig("--global", "core.hooksPath", dir); err != nil {
			return res, err
		}
	}
	return res, nil
}

// Uninstall removes only the hooks this tool wrote, restores anything it
// chained, and clears core.hooksPath if it is now empty of our hooks.
func Uninstall(global bool, override string) (Result, error) {
	res := Result{Global: global}
	dir, err := targetDir(global, override)
	if err != nil {
		return res, err
	}
	res.HooksPath = dir

	for _, name := range Names {
		path := filepath.Join(dir, name)
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if !bytes.Contains(body, []byte(marker)) {
			// Not ours. Leave it alone and say so.
			continue
		}
		if err := os.Remove(path); err != nil {
			return res, err
		}
		res.Installed = append(res.Installed, path)

		if saved := path + chainedSuffix; fileExists(saved) {
			if err := os.Rename(saved, path); err != nil {
				return res, err
			}
			res.Chained = append(res.Chained, name)
		}
	}

	if global {
		// Only give up the config if the directory is now empty of hooks. The
		// user may have pointed us at a hooks dir they already had (via
		// --hooks-path), and unsetting core.hooksPath would disable every
		// other hook living there.
		if cur, _ := gitConfig("--global", "core.hooksPath"); filepath.Clean(cur) == filepath.Clean(dir) && dirIsEmpty(dir) {
			_ = exec.Command("git", "config", "--global", "--unset", "core.hooksPath").Run()
			res.ClearedConfig = true
		}
	}
	return res, nil
}

// dirIsEmpty reports whether a directory holds no entries at all.
func dirIsEmpty(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) == 0
}

// shellQuote renders a path as a single-quoted POSIX shell word. Go's %q is
// not shell quoting: it leaves $ and backticks untouched, which the shell
// would then expand.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// preserveExisting moves a foreign hook aside so the new script can call it.
// Returns whether anything was preserved.
func preserveExisting(path string) (bool, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return false, nil // nothing there
	}
	if bytes.Contains(body, []byte(marker)) {
		// Ours from a previous install; a chained copy may already exist.
		return fileExists(path + chainedSuffix), nil
	}
	saved := path + chainedSuffix
	if fileExists(saved) {
		return false, fmt.Errorf("refusing to overwrite %s: a chained hook is already saved there", saved)
	}
	if err := os.Rename(path, saved); err != nil {
		return false, fmt.Errorf("could not preserve existing hook %s: %w", path, err)
	}
	if err := os.Chmod(saved, 0o755); err != nil {
		return false, err
	}
	return true, nil
}

// script renders the hook body. The chained branch runs the pre-existing hook
// first and honours its exit code, so installing secret-guard never silently
// disables another tool's hook.
func script(name, self string, chained bool) []byte {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString(marker + "\n")
	b.WriteString("# Remove with: secret-guard hook uninstall\n\n")

	if chained {
		if name == "pre-push" {
			// pre-push is handed its ref updates on stdin, and stdin can only
			// be consumed once. Read it here, unconditionally: doing it inside
			// the "is the chained hook runnable" branch means that if that
			// hook is ever deleted, $refs is empty, secret-guard sees no ref
			// updates, scans nothing and exits 0 - a silent fail-open in the
			// last check before a push leaves the machine.
			b.WriteString("refs=$(cat)\n\n")
		}
		fmt.Fprintf(&b, "prev=\"$0%s\"\n", chainedSuffix)
		b.WriteString("if [ -x \"$prev\" ]; then\n")
		if name == "pre-push" {
			b.WriteString("  printf '%s\\n' \"$refs\" | \"$prev\" \"$@\" || exit $?\n")
		} else {
			b.WriteString("  \"$prev\" \"$@\" || exit $?\n")
		}
		b.WriteString("fi\n\n")
	}

	fmt.Fprintf(&b, "guard=%s\n", shellQuote(self))
	b.WriteString("command -v \"$guard\" >/dev/null 2>&1 || guard=secret-guard\n")
	b.WriteString("command -v \"$guard\" >/dev/null 2>&1 || {\n")
	b.WriteString("  echo 'secret-guard: binary not found; skipping scan' >&2\n")
	b.WriteString("  exit 0\n")
	b.WriteString("}\n\n")

	switch name {
	case "pre-commit":
		b.WriteString("exec \"$guard\" --staged\n")
	case "pre-push":
		if chained {
			b.WriteString("printf '%s\\n' \"$refs\" | \"$guard\" --pre-push\n")
			b.WriteString("exit $?\n")
		} else {
			b.WriteString("exec \"$guard\" --pre-push\n")
		}
	}
	return []byte(b.String())
}

// targetDir picks the hooks directory: a shared one for global installs, the
// repo's own for local.
func targetDir(global bool, override string) (string, error) {
	if override != "" {
		return filepath.Abs(override)
	}
	if !global {
		out, err := exec.Command("git", "rev-parse", "--git-path", "hooks").Output()
		if err != nil {
			return "", fmt.Errorf("not inside a git repository: %w", err)
		}
		p := strings.TrimSpace(string(out))
		abs, err := filepath.Abs(p)
		if err != nil {
			return p, nil
		}
		return abs, nil
	}
	if cfg := os.Getenv("XDG_CONFIG_HOME"); cfg != "" {
		return filepath.Join(cfg, "git", "hooks"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "git", "hooks"), nil
}

// selfPath resolves this binary to an absolute path so the hook keeps working
// regardless of the PATH a GUI git client happens to have.
func selfPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "secret-guard", nil
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if runtime.GOOS == "windows" {
		return exe, nil
	}
	return exe, nil
}

func gitConfig(scope, key string) (string, error) {
	out, err := exec.Command("git", "config", scope, "--get", key).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func setGitConfig(scope, key, val string) error {
	return exec.Command("git", "config", scope, key, val).Run()
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
