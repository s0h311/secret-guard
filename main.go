// Command secret-guard finds credentials that are about to be committed.
//
//	secret-guard                     scan uncommitted changes (incl. untracked)
//	secret-guard --staged            scan what a commit would contain
//	secret-guard --commit <hash>     scan one commit
//	secret-guard --diff <file|->     scan a patch file, or - for stdin
//	secret-guard hook install        install the git hooks
//
// Exit codes: 0 clean, 1 findings, 2 usage or internal error.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/s0h311/secret-guard/internal/diff"
	"github.com/s0h311/secret-guard/internal/gitx"
	"github.com/s0h311/secret-guard/internal/hook"
	"github.com/s0h311/secret-guard/internal/report"
	"github.com/s0h311/secret-guard/internal/scan"
)

const version = "0.1.0"

const usage = `secret-guard - find credentials before they reach a remote

USAGE
  secret-guard [flags]                 scan uncommitted changes (tracked + untracked)
  secret-guard --staged                scan the index, i.e. what a commit would contain
  secret-guard --commit <hash>         scan a single commit
  secret-guard --diff <file|->         scan a unified diff file, or - for stdin
  secret-guard hook install [--global] install pre-commit + pre-push hooks
  secret-guard hook uninstall [--global]

FLAGS
  --json           machine-readable output
  --no-color       disable colour (also honours NO_COLOR)
  --version        print version
  -h, --help       this message

EXIT CODES
  0  no findings      1  findings      2  usage or internal error

SUPPRESSING A FALSE POSITIVE
  Append "secret-guard:allow <reason>" to the offending line.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Stdin))
}

func run(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	if len(args) > 0 && args[0] == "hook" {
		return runHook(args[1:], stdout, stderr)
	}

	fs := flag.NewFlagSet("secret-guard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }

	var (
		asJSON  = fs.Bool("json", false, "machine-readable output")
		staged  = fs.Bool("staged", false, "scan the index")
		commit  = fs.String("commit", "", "scan a single commit")
		patch   = fs.String("diff", "", "scan a unified diff file, or - for stdin")
		prePush = fs.Bool("pre-push", false, "read git pre-push ref updates on stdin")
		noColor = fs.Bool("no-color", false, "disable colour output")
		showVer = fs.Bool("version", false, "print version")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVer {
		fmt.Fprintf(stdout, "secret-guard %s\n", version)
		return 0
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "secret-guard: unexpected argument %q\n\n", fs.Arg(0))
		fmt.Fprint(stderr, usage)
		return 2
	}
	if *noColor {
		os.Setenv("NO_COLOR", "1")
	}

	files, source, err := gather(*staged, *commit, *patch, *prePush, stdin, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "secret-guard: %v\n", err)
		return 2
	}

	findings := scan.Scan(files)

	if *asJSON {
		if err := report.JSON(stdout, findings); err != nil {
			fmt.Fprintf(stderr, "secret-guard: %v\n", err)
			return 2
		}
	} else {
		report.Human(stdout, findings, source)
	}

	if len(findings) == 0 {
		return 0
	}
	if !*asJSON && (*prePush || *staged) {
		fmt.Fprint(stdout, bypassHint(*prePush))
	}
	return 1
}

// gather resolves the requested input into parsed diff files. Exactly one
// source is used; a piped stdin is treated as a patch when no flag says
// otherwise, which makes `git diff | secret-guard` work with no flags.
func gather(staged bool, commit, patch string, prePush bool, stdin io.Reader, stderr io.Writer) ([]diff.File, string, error) {
	switch {
	case prePush:
		return gatherPrePush(stdin, stderr)

	case patch != "":
		if patch == "-" {
			f, err := diff.Parse(stdin)
			return f, "stdin", err
		}
		fh, err := os.Open(patch)
		if err != nil {
			return nil, "", err
		}
		defer fh.Close()
		f, err := diff.Parse(fh)
		return f, patch, err

	case commit != "":
		if !gitx.InRepo() {
			return nil, "", errors.New("not inside a git repository")
		}
		f, err := gitx.Commit(commit)
		return f, "commit " + commit, err

	case staged:
		if !gitx.InRepo() {
			return nil, "", errors.New("not inside a git repository")
		}
		f, err := gitx.Staged()
		return f, "staged changes", err
	}

	// No explicit source: scan the working tree.
	//
	// Stdin is deliberately NOT auto-detected here. "stdin is not a terminal"
	// is true in plenty of contexts where no diff is coming - CI runners,
	// background jobs, nohup - and reading it then blocks forever instead of
	// doing the obvious thing. Piping is still supported, explicitly, via
	// `--diff -`.
	if !gitx.InRepo() {
		return nil, "", errors.New("not inside a git repository (pass --diff <file|-> to scan a patch)")
	}
	f, err := gitx.WorkingTree()
	return f, "working tree", err
}

// gatherPrePush reads the ref updates git feeds a pre-push hook on stdin and
// scans only the commits actually being pushed.
func gatherPrePush(stdin io.Reader, stderr io.Writer) ([]diff.File, string, error) {
	raw, err := io.ReadAll(stdin)
	if err != nil {
		return nil, "", err
	}

	var (
		all  []diff.File
		refs []string
		seen = map[string]bool{}
	)
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		localRef, localSHA, remoteSHA := parts[0], parts[1], parts[3]

		if localSHA == gitx.ZeroSHA {
			continue // branch deletion: nothing is being added
		}

		base := remoteSHA
		count := 0
		if remoteSHA == gitx.ZeroSHA {
			// The remote has never seen this ref, so there is no remote SHA to
			// diff against. Ask git what this push would newly publish.
			b, n, err := gitx.BaseForNewBranch(localSHA)
			if errors.Is(err, gitx.ErrNothingNew) {
				continue
			}
			if err != nil {
				fmt.Fprintf(stderr,
					"secret-guard: WARNING: could not determine a base for new ref %s (%v); skipping scan of this ref\n",
					localRef, err)
				continue
			}
			base, count = b, n
		} else if n, err := gitx.CountCommits(base, localSHA); err == nil {
			count = n
		}

		if count > gitx.MaxPushCommits {
			fmt.Fprintf(stderr,
				"secret-guard: WARNING: %s pushes %d commits (cap %d); skipping scan of this ref to avoid stalling the push\n",
				localRef, count, gitx.MaxPushCommits)
			continue
		}

		files, err := gitx.Range(base, localSHA)
		if err != nil {
			fmt.Fprintf(stderr, "secret-guard: WARNING: could not diff %s..%s: %v\n", base, localSHA, err)
			continue
		}
		all = append(all, files...)
		if !seen[localRef] {
			seen[localRef] = true
			refs = append(refs, localRef)
		}
	}

	src := "the commits being pushed"
	if len(refs) > 0 {
		src = "the commits being pushed to " + strings.Join(refs, ", ")
	}
	return all, src, nil
}

func bypassHint(prePush bool) string {
	cmd := "git commit --no-verify"
	if prePush {
		cmd = "git push --no-verify"
	}
	return fmt.Sprintf("\nIf these are all false positives, bypass with:\n  %s\n", cmd)
}

func runHook(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, "secret-guard: hook needs a subcommand: install or uninstall\n")
		return 2
	}
	sub := args[0]

	fs := flag.NewFlagSet("secret-guard hook "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	global := fs.Bool("global", false, "apply to every repository via core.hooksPath")
	hooksPath := fs.String("hooks-path", "", "install into this directory instead of the default")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	switch sub {
	case "install":
		res, err := hook.Install(*global, *hooksPath)
		if err != nil {
			fmt.Fprintf(stderr, "secret-guard: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "Installed secret-guard hooks in %s\n", res.HooksPath)
		for _, p := range res.Installed {
			fmt.Fprintf(stdout, "  + %s\n", p)
		}
		for _, n := range res.Chained {
			fmt.Fprintf(stdout, "  ~ kept your existing %s and chained it (it runs first)\n", n)
		}
		if res.Global {
			fmt.Fprintf(stdout, "  * set git config --global core.hooksPath %s\n", res.HooksPath)
			fmt.Fprint(stdout, "\nNOTE: a global core.hooksPath overrides each repo's own .git/hooks,\n"+
				"so per-repo hooks that are not in this directory will stop running.\n")
		}
		fmt.Fprint(stdout, "\nUndo with: secret-guard hook uninstall")
		if res.Global {
			fmt.Fprint(stdout, " --global")
		}
		fmt.Fprintln(stdout)
		return 0

	case "uninstall":
		res, err := hook.Uninstall(*global, *hooksPath)
		if err != nil {
			fmt.Fprintf(stderr, "secret-guard: %v\n", err)
			return 2
		}
		if len(res.Installed) == 0 {
			fmt.Fprintf(stdout, "No secret-guard hooks found in %s\n", res.HooksPath)
			return 0
		}
		fmt.Fprintf(stdout, "Removed secret-guard hooks from %s\n", res.HooksPath)
		for _, p := range res.Installed {
			fmt.Fprintf(stdout, "  - %s\n", p)
		}
		for _, n := range res.Chained {
			fmt.Fprintf(stdout, "  ~ restored your original %s\n", n)
		}
		if res.ClearedConfig {
			fmt.Fprint(stdout, "  * unset git config --global core.hooksPath\n")
		} else if res.Global {
			fmt.Fprintf(stdout, "  * left core.hooksPath pointing at %s (other hooks live there)\n", res.HooksPath)
		}
		return 0

	default:
		fmt.Fprintf(stderr, "secret-guard: unknown hook subcommand %q\n", sub)
		return 2
	}
}
