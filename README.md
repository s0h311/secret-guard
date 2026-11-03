# secret-guard

A small CLI that finds credentials in a change before they reach a remote, and
installs itself as a git hook so you stop having to remember to run it.

```
$ secret-guard
.env
  ⚠ env-file-committed — a dotenv file is being committed; these hold real credentials and belong in .gitignore
    value: .env  (tier 4, file-level)

.env:1
  ⚠ env-secret — dotenv entry "DB_PASSWORD" holds a 19-character value
    value: supe********word  (tier 2, keyword-assignment)

config.tf:1
  ⚠ aws-access-key-id — AWS access key id (AKIA/ASIA followed by 16 uppercase chars)
    value: AKIA********MPLE  (tier 1, provider-pattern)

3 suspected secrets in working tree
False positive? append secret-guard:allow to the line.
```

## Install

```sh
go install github.com/s0h311/secret-guard@latest   # needs Go 1.26+
secret-guard hook install --global                 # protect every repo
```

Or from a clone: `make install && make hook`.

`hook install` writes **two** hooks:

| hook | scans | why |
|---|---|---|
| `pre-commit` | `git diff --cached` | catches it while the fix is cheap — just unstage the line |
| `pre-push` | every commit in the pushed range, walked one by one | catches what pre-commit can't see: commits from a rebase, merge, `--amend`, another machine, or one `--no-verify` |

The pushed range is walked **per commit**, not diffed end to end. A secret
added in one commit and deleted in the next nets out to nothing in a
two-endpoint diff, yet both commits are still being pushed and the secret stays
recoverable in the remote's history forever.

Drop `--global` to install into the current repo's `.git/hooks` instead.
Undo with `secret-guard hook uninstall [--global]`.

When a scan fails, the documented bypass is printed with it:

```sh
git push --no-verify     # or: git commit --no-verify
```

## Usage

```sh
secret-guard                        # uncommitted changes, including untracked files
secret-guard --staged               # what a commit would contain
secret-guard --commit <hash>        # one commit
secret-guard --diff change.patch    # a patch file
git diff main.. | secret-guard --diff -   # a diff on stdin
secret-guard --json                 # machine-readable
```

Exit codes: **0** clean, **1** findings, **2** usage or internal error. The
three are distinct so CI can tell "the tool found something" apart from "the
tool broke".

Suppress a false positive by appending a marker to the line — any comment
syntax works, since the marker is matched as plain text:

```python
API_KEY = "AKIAIOSFODNN7EXAMPLE"  # secret-guard:allow docs example
```

## How it decides

Every input is converted to a unified diff, and **only added (`+`) lines are
scanned** — you are never shown a finding for code you didn't just write. Line
numbers come from the hunk headers, so they point at the real post-image line.

Detection runs in three tiers of descending confidence. Each finding names its
tier and gives a reason, so you can argue with it:

1. **Provider patterns** — shapes unique to a vendor: `AKIA…`, `ghp_…`,
   `xox[baprs]-…`, `sk_live_…`, `AIza…`, `sk-…`, PEM private-key headers, JWTs,
   and connection strings with an inline password. Near-zero false positives.
2. **Keyword assignment** — a key that *names* a credential assigned a
   plausible literal. The key is split into words (`db_password`, `dbPass`,
   `DB-PASSWORD` all normalise alike) and matched whole-word, which is how
   `dbPass` is caught while `bypass` and `public_key` are not. Values that are
   placeholders (`changeme`, `your_token_here`, `${VAR}`, `<redacted>`), type
   names (`string`), env lookups (`os.environ[...]`), or URLs without
   credentials are rejected.
3. **Entropy** — Shannon entropy ≥ 4.0 bits/char over a ≥24-char opaque token,
   and *only* on a line that otherwise mentions a credential **as a whole
   word**. Short ambiguous words don't count as context here — bare `pwd` is
   usually the shell command and `pass` is an English word — though both still
   count when they name a key. This tier is what catches key shapes nobody
   wrote a regex for, and it is also where false positives live, which is why
   it is the most tightly gated. On 200k lines of random text it produces one
   finding: the real AWS key planted in them.

Dotenv files (`.env`, `.env.local`, `*.env`, `.envrc`) are a **high-signal
class**: there the key name alone is enough context and no quoting is needed,
plus a newly added `.env` is a finding in its own right — the fix is to
gitignore the file regardless of what's currently in it. Template variants
(`.env.example`, `.sample`, `.template`, `.dist`) are excluded, since they are
meant to be committed.

Secrets are **masked** in all output (`AKIA********MPLE`). The tool should not
be the thing that pastes your credential into a CI log.

Skipped by default: lockfiles, `*.min.js`, `*.map`, binaries and images, and
`vendor/`, `node_modules/`, `dist/`, `build/`, `target/`. All high-entropy
noise with a near-zero real-secret rate.

## Where it fails

Honest limits, roughly in order of how likely they are to bite you:

- **It is a regex-and-entropy scanner, not an oracle.** A secret that looks
  like ordinary text — a short password with no digits assigned to a key not
  named like a credential (`value = "correct horse"`) — is invisible to all
  three tiers.
- **It only sees added lines in the change you point it at.** A secret already
  sitting in your history is not reported by any mode except `--commit` on the
  commit that introduced it. This tool prevents new leaks; it does not audit a
  repo. (`git log -p | secret-guard --diff -` is a crude whole-history sweep.)
- **Client-side hooks are advisory.** `--no-verify` bypasses them, a teammate
  without the tool installed is unprotected, and nothing stops a push made from
  another machine. Only a server-side check (`pre-receive`, GitHub push
  protection, or a CI job) is actually unbypassable. That is a deliberate scope
  choice, not an oversight.
- **A global `core.hooksPath` overrides each repo's own `.git/hooks`.** That is
  how git works, and it means per-repo hooks living outside that directory stop
  running. `hook install --global` prints this warning, refuses to repoint an
  existing `core.hooksPath`, and chains any `pre-commit`/`pre-push` it finds
  rather than clobbering it — but if your repos rely on unmanaged local hooks,
  prefer the per-repo install.
- **Dotenv detection is deliberately aggressive.** Any sufficiently long or
  high-entropy value in a committed `.env` is flagged even when harmless, on
  the view that a committed `.env` is itself the problem.
- **Throughput is roughly 4 MB/s** of diff, single-threaded. Fine for a commit
  or a push; a whole-history sweep of a large repo will take a while.
- **Entropy is blind to encoding.** Base64-encoded *non*-secrets (an inline
  certificate, a test fixture, a data URI) on a line that happens to mention a
  token will be flagged. Suppress with `secret-guard:allow`.
- **Line truncation.** Lines are examined up to 4096 characters, so a secret
  buried past that point in a single enormous line is missed. (The
  `secret-guard:allow` marker is matched against the whole line, so
  suppression still works on long lines.) Lines containing NUL bytes stop the
  scan of that file, on the assumption it is binary.
- **Standard base64 secrets containing `/` may be split.** `/` and `.` are
  excluded from entropy candidates so that paths and import specifiers don't
  score as high-entropy blobs; a standard-alphabet base64 secret with slashes
  can therefore break into segments shorter than the 24-char threshold.
  base64url secrets (`-`, `_`) are unaffected.
- **A huge first push is skipped, loudly.** A new branch whose unpushed history
  exceeds 1000 commits prints a warning and is not scanned, rather than
  stalling the push for minutes.
- **The hooks fail open.** If the `secret-guard` binary is missing when a hook
  runs (uninstalled, moved, a GUI client with a different `PATH`), the hook
  prints a warning to stderr and exits 0 rather than blocking every commit in
  every repo. That is the right DX trade-off, but it means protection can
  disappear quietly — the warning is the only signal.
- **Rotation is still on you.** A finding means the secret is in your working
  tree or history. Deleting the line does not un-leak it if it was ever pushed
  — rotate the credential.

## Development

```sh
make test      # unit + end-to-end tests
make lint      # go vet
```

Three layers of tests, at the seams that actually matter:

- `internal/diff` — hunk-header arithmetic produces correct post-image line
  numbers across multiple hunks. This is the subtlest logic in the tool.
- `internal/scan` — a table of true positives per tier *and* an equal number of
  negatives (placeholders, env lookups, `bypass`, `public_key`, lockfiles,
  `.env.example`). The false-positive cases are the ones that matter: a noisy
  scanner gets disabled, and a disabled scanner catches nothing.
- `internal/diff` also covers plain `diff -u` multi-file patches, combined
  merge diffs (`@@@` headers), and git's quoted non-ASCII paths.
- `e2e_test.go` — builds the binary and runs it: exit codes, `--json` shape,
  masking, and real-git tests that install the hooks into a temp repo and
  confirm a commit and a push carrying a secret are genuinely blocked, that
  `--no-verify` still works, that a scan from a subdirectory still finds
  untracked files, that a repo with no HEAD is scanned, and that a secret
  added-then-deleted inside a pushed range is still caught.

## AI assistance

This was built with AI assistance (Claude Code). `AI_LOG.md` contains the full
design interrogation that preceded the code and the prompts used, including the
points where I overrode the model's recommendation. See that file for an honest
account of time spent.
