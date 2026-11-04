# secret-guard

Finds passwords and API keys in a change before they reach a remote, and
installs itself as a git hook so you don't have to remember to run it.

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

Only **added lines** are ever scanned, so you never get a finding for code you
didn't just write. Secret values are **masked** in the output — the tool
shouldn't be the thing that pastes your credential into a CI log.

## Install

```sh
go install github.com/s0h311/secret-guard@latest   # needs Go 1.26+
secret-guard hook install --global                 # protect every repo
```

From a clone: `make install && make hook`.

`hook install` writes two hooks:

| hook | scans | why |
|---|---|---|
| `pre-commit` | the staged diff | catches it while the fix is cheap — just unstage the line |
| `pre-push` | every commit in the pushed range | catches what pre-commit can't see: rebases, merges, `--amend`, another machine, one `--no-verify` |

Drop `--global` to install into the current repo only. Undo with
`secret-guard hook uninstall [--global]`. An existing hook is chained, never
overwritten.

Bypass a blocked commit or push with `--no-verify`.

## Usage

```sh
secret-guard                        # uncommitted changes, including untracked files
secret-guard --staged               # what a commit would contain
secret-guard --commit <hash>        # one commit
secret-guard --diff change.patch    # a patch file
git diff main.. | secret-guard --diff -
secret-guard --json                 # machine-readable
```

Exit codes: **0** clean, **1** findings, **2** usage or internal error.

Suppress a false positive by appending a marker to the line (any comment
syntax works):

```python
API_KEY = "AKIAIOSFODNN7EXAMPLE"  # secret-guard:allow docs example
```

## The three tiers

Detection runs in tiers of descending confidence. Each finding names its tier
and gives a reason, so you can argue with it.

**Tier 1 — provider patterns.** Shapes unique to a vendor: `AKIA…`, `ghp_…`,
`xox[baprs]-…`, `sk_live_…`, `AIza…`, `sk-…`, PEM private-key headers, JWTs,
and connection strings with an inline password. Near-zero false positives.

**Tier 2 — keyword assignment.** A key that *names* a credential assigned a
plausible literal. The key is split into words, so `db_password`, `dbPass` and
`DB-PASSWORD` all match alike — which is how `dbPass` is caught while `bypass`
and `public_key` are not. Placeholders (`changeme`, `your_token_here`,
`${VAR}`), type names (`string`) and env lookups (`os.environ[...]`) are
rejected.

**Tier 3 — entropy.** Shannon entropy ≥ 4.0 bits/char over a ≥24-char opaque
token, and only on a line that mentions a credential as a whole word. This
catches key shapes nobody wrote a regex for. It's also where false positives
live, so it's the most tightly gated tier.

Plus a **dotenv class**: in `.env` files the key name alone is enough context,
and a newly added `.env` is a finding in itself. `.env.example`, `.sample`,
`.template` and `.dist` are excluded.

Skipped by default: lockfiles, `*.min.js`, `*.map`, binaries, and `vendor/`,
`node_modules/`, `dist/`, `build/`.

## Where it fails

- **It's a regex-and-entropy scanner, not an oracle.** A short wordlike
  password on a key not named like a credential is invisible to all three tiers.
- **It only sees the change you point it at**, not your existing history. This
  prevents new leaks; it doesn't audit a repo.
- **Client hooks are advisory.** `--no-verify` bypasses them, and a teammate
  without the tool installed is unprotected. Only a server-side check or a CI
  job is unbypassable.
- **A global `core.hooksPath` overrides each repo's `.git/hooks`**, so
  unmanaged per-repo hooks stop running. Install prints this warning; prefer
  the per-repo install if that affects you.
- **The hooks fail open.** If the binary is missing when a hook runs, it warns
  and exits 0 rather than blocking every commit everywhere.
- **Rotation is still on you.** Deleting the line doesn't un-leak a secret that
  was ever pushed.

## Development

```sh
make test   # unit + end-to-end tests
make lint   # go vet
```

Tests sit at three seams: the diff parser's line arithmetic, a detector table
of true positives *and* negatives, and end-to-end runs that install the hooks
into a real temp repo and confirm a commit and a push carrying a secret are
genuinely blocked.

## AI assistance

Built with AI assistance (Claude Code). `AI_LOG.md` has the full design
interrogation, the prompts, the bugs found along the way, and an honest note on
time spent.
