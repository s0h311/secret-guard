# AI assistance log

Built with Claude Code (Opus 5). Two phases: a design interrogation where I was
questioned about every decision before any code existed, then implementation.

**Time:** roughly 90 minutes wall-clock end to end, of which the design
interrogation was about 25. The brief says "about 30 minutes"; this is more than
that, and I'd rather say so than pretend otherwise. The brief explicitly allows
any tools and asks for the prompts, so what follows is the actual record.

---

## Phase 1 — design interrogation

I did not start from "write me a secret scanner". I started by asking to be
grilled on the design, so the decisions were made and challenged before any
code was written.

### Initial prompt

> Secret Finder
> Developers sometimes commit passwords or keys by mistake. Build a CLI tool that finds
> them in a change.
> • Input: a git diff (file or stdin), a commit hash, or the current changes in the
> working directory
> • Output: a list of findings with file and line, and a short reason for each
> Rules
> • Start from scratch. CLI only. Use any language, tools, or AI you want.
> • Time: about 30 minutes.
> • The repo must include a short README (how to run it, where it fails) and 2-3
> tests.
> • If you used AI, include your prompts or logs.
> • Later, we may ask you to explain your work.
>
> I want it to be super simple and option to integrate it as a global git pre push
> hook. Good DX is important

### Round 1 — four questions

**Language and runtime.** Options: Go stdlib-only static binary / single-file
Node / single-file Python. Argument for Go: for a *global* hook, a
self-contained binary is the whole DX story — no `node_modules`, no venv, no
interpreter drift on a teammate's machine. **I chose Go.**

**Detection strategy.** Options: all three tiers (provider regex + keyword
assignment + gated entropy) / tiers 1–2 only / tier 1 only. **I chose all
three, and added a requirement of my own: treat `.env` files specially.** That
turned out to be the single highest-value feature in the tool — it is the most
common real leak and the generic heuristics handle it badly.

**Input model.** All three input modes collapse to a unified diff internally,
scanning only added lines. The open question was whether the no-arg
working-directory mode includes untracked files. **I chose to include them** —
a brand-new `.env` is exactly the case `git diff` cannot see.

**Hook installation.** Options: global + local with chaining / global only,
refuse on conflict / print the script and let the user wire it up. **I chose
global + local with chaining** — and noted that I thought **pre-commit made
more sense than pre-push**, which is where my own brief got revised.

### Round 2 — pushback on my pre-commit instinct

I was told pre-commit and pre-push are not competing options, because they fail
differently: pre-commit stops the secret while the fix is cheap, but cannot see
commits that arrived by rebase, merge, `--amend`, from another machine, or
behind a single `--no-verify`. pre-push sees the whole pushed range regardless
of origin, but by then the secret is in history.

**My response: "Can we implement pre-receive hooks? So its always safe."**

The answer corrected a real misconception of mine: `pre-receive` runs on the
*server*, which is why it is unbypassable — but GitHub.com does not let you
install one (that is GitHub Enterprise Server only). It is also a hard wall
with no escape hatch, so a false positive blocks a legitimate push outright.

Also settled in this round: the `.env` high-signal class (any `KEY=value` with
a real-looking value, plus a file-level finding for a newly added `.env`,
excluding `.env.example`), human output with `--json` and **masked** secret
values, and suppression via an inline `secret-guard:allow` comment plus
built-in path skips, with **no config file** — the simplicity tax wasn't worth
it.

### Round 3 — scoping the server-side idea

Options for pre-receive: ship it fully / document it with zero extra code /
drop it. **I chose to drop it entirely** — it cannot be demoed on GitHub.com,
and I'd rather ship a smaller thing that works than gesture at one that can't
be exercised. Also settled: `go install` + `hook install --global` as the
install path; new-branch pushes fall back to a computed base with a commit cap
and a loud warning rather than hanging; three test layers (parser line math,
detector table with negatives, E2E binary run).

### Round 4 — the honest-scope question

I was told plainly that what I had specified was more than 30 minutes of work,
and asked whether to cut it down, build it all and say so, or build it all
quietly. **I chose to build it all and be transparent about the time**, which
is why the note at the top of this file exists.

The hook-event question also came back, since my pre-receive detour had
replaced it. With no server-side backstop, I chose **both hooks**.

---

## Phase 2 — implementation

### Prompt

> implement

That was the entire implementation prompt. The design interrogation had already
fixed every decision, so there was nothing left to specify.

Work proceeded test-first, one vertical slice at a time, against the three
seams agreed in round 3.

### What the tests caught

Writing the tests first paid for itself three times:

1. **The word-like value filter rejected real passwords.** I had a heuristic
   that treats letters-only values as words rather than secrets, to keep
   `APP_NAME=secret-guard` quiet. It also rejected
   `DB_PASSWORD=supersecretpassword`. Fix: skip that filter when the *key* is
   explicitly a credential — the key name is decisive context.

2. **The entropy candidate pattern swallowed the key.** `=` was in its
   character class, so `DB_PASSWORD=your_password_here` matched as one 30-char
   high-entropy blob and was flagged — in a `.env.example`, which is meant to
   be committed. Fix: allow `=` only as trailing base64 padding.

3. **Keyword matching missed `dbPass`.** The keyword regex had
   `password|passwd|pwd` but not bare `pass`, and adding `pass` to a regex
   would also match `bypass` and `compass`. Fix: split the key into words on
   snake/kebab/camel boundaries and match whole words. `dbPass` → `[db, pass]`
   hits; `bypass` → `[bypass]` doesn't. This is strictly better than the regex
   it replaced, and the two cases are now regression tests.

### Two more bugs manual testing found, and one design reversal

**Untracked files were invisible from a subdirectory.** `git ls-files --others`
is scoped to the current directory and prints CWD-relative paths, whereas
`git diff` is repo-wide and prints root-relative ones. I had joined the former
onto the repo root, so from `services/api/` the resulting path didn't exist,
`os.Stat` failed, and the file was skipped by an error branch that stayed
silent. Fix: run `ls-files` from the repo top level. Now a regression test.

**Stdin auto-detection could hang forever.** I had "stdin is not a terminal →
treat it as a diff", so `git diff | secret-guard` worked with no flags. But
"not a terminal" is also true in CI runners, background jobs and `nohup`, where
no diff is ever coming — and the tool then blocks on a read that never
returns instead of scanning the working tree. I hit this for real while
testing. I reversed the decision: stdin is now only read when asked for
explicitly, via `--diff -`. Less magic, one documented flag, cannot hang.

**The entropy tier fired on random text.** A throughput check on a synthetic
200k-line diff of random letters reported **696 findings**. The cause was the
same class of mistake as the `dbPass` one, in the other direction: tier 3's
gate asked "does this line contain a credential word" with a substring regex,
so any three characters that happened to spell `pwd` unlocked it. Making the
gate word-aware cut it to 61; excluding words too short or common to carry a
line alone (`pwd` is the shell command, `pass` is an English word — both still
count as *key* names) cut it to **1**, which was the real AWS key planted in
the file. Both halves are now regression tests.

### The bug the tests did *not* catch

Manual verification against a real bare remote found a **silent false negative
in my own pre-push path**: a push of a branch the remote had never seen
reported "no secrets found" while the commits plainly contained an AWS key.

Cause: for a new branch there is no remote SHA to diff against, and my fallback
walked a candidate list down to the local `master`. The merge base of a branch
with itself is its own tip, so the computed range was empty and the scan
examined nothing.

Fix: ask git the question directly — `rev-list <local> --not --remotes` is
precisely "commits this push would newly publish". Root commits diff against
the empty tree, so the first commit in a repository is still scanned. This is
now covered by a dedicated regression test that pushes to a real bare remote
and asserts the push is blocked.

This is the failure I'd flag in a review of my own work: the unit tests were
green and the feature was broken. Only exercising it against real git found it,
which is why the E2E layer drives actual `git commit` and `git push`.

Two of the three bugs above share that shape: green unit tests, broken
behaviour, found only by running the thing against real git in a real
directory. The fix in each case was a regression test at the level where the
bug actually lived.

### Phase 3 — adversarial code review

I then had the finished code reviewed by a separate agent with no memory of
writing it, which returned 11 findings. I verified each against real git before
changing anything; all 11 held up. The serious ones were all **silent
misses** — the worst failure mode for this kind of tool, because it reports
"✓ no secrets found" and the user believes it:

1. **A plain `diff -u` multi-file patch collapsed into its last file.** The
   parser flushed only on `diff --git`, which non-git patches don't have. A
   secret in the first file was reported under the last file's path — and if
   that last file matched a skip rule, the whole patch reported clean.
2. **`git diff base..tip` misses a secret added then deleted inside the pushed
   range.** It compares trees, so the two commits cancel out, while both are
   still being pushed and the secret stays in the remote's history forever.
   Fixed by walking the range per commit.
3. **A chained pre-push could fail open.** `refs=$(cat)` sat inside the
   `if [ -x "$prev" ]` branch, so if the chained hook was ever deleted the ref
   list was empty, secret-guard saw no refs, scanned nothing, and exited 0.
4. **`--commit <merge-sha>` always reported clean.** `diff-tree -p` prints
   nothing for a merge without `--cc`, so a secret added while resolving a
   conflict was invisible. Fixing it also required teaching the parser combined
   diffs, where ` -AAA` is "removed from parent 2", not a context line — which
   had been throwing line numbers off.
5. **A repo with no HEAD scanned nothing** — exactly the `git init && git add .`
   moment when a `.env` gets staged.
6. **`api_key` gated nothing in tier 3.** `secretWordPairs` were compared
   word-by-word, but `splitIdentifier("api_key")` yields `["api","key"]`, never
   the joined `"apikey"`. Fixed by comparing adjacent pairs.
7. **Suppression was checked after truncation**, so a `secret-guard:allow`
   marker past 4096 characters was sliced off and the finding couldn't be
   silenced at all.

Plus four smaller ones: `git`'s quoted non-ASCII paths were left quoted
(defeating the `.env` rules), `hook uninstall --global` unset `core.hooksPath`
even when other hooks lived there, the Makefile ignored `GOBIN`, and Go's `%q`
was used as shell quoting (it doesn't escape `$` or backticks).

Six of the eleven now have regression tests; the rest are single-line fixes
whose behaviour is covered by existing cases.

The lesson I'd draw: my own testing was good at "does the detector work" and
weak at "does the plumbing lie to me". Every serious finding was in the git
plumbing or the parser, not the detection logic — and all of them reported
success while doing nothing.
