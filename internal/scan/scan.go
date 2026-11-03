// Package scan finds credentials in the added lines of a parsed diff.
//
// Detection runs in three tiers of descending confidence, and every finding
// names the tier that produced it so the output can be argued with:
//
//  1. provider patterns  - shapes unique to a vendor (AKIA..., ghp_..., PEM blocks)
//  2. keyword assignment - password/token/api_key assigned a plausible literal
//  3. entropy            - long opaque strings, only in secret-ish context
//
// Dotenv-shaped files are treated as a high-signal class of their own: there
// the key name alone is enough context, no quoting required.
package scan

import (
	"fmt"
	"math"
	"strings"

	"github.com/s0h311/secret-guard/internal/diff"
)

// Tier labels the confidence class a finding came from.
type Tier int

const (
	TierProvider Tier = 1
	TierKeyword  Tier = 2
	TierEntropy  Tier = 3
	TierFile     Tier = 4
)

func (t Tier) String() string {
	switch t {
	case TierProvider:
		return "provider-pattern"
	case TierKeyword:
		return "keyword-assignment"
	case TierEntropy:
		return "entropy"
	case TierFile:
		return "file-level"
	}
	return "unknown"
}

// Finding is one suspected credential. Masked never contains the full secret.
type Finding struct {
	Path   string `json:"path"`
	Line   int    `json:"line"` // 0 for file-level findings
	Rule   string `json:"rule"`
	Tier   int    `json:"tier"`
	Reason string `json:"reason"`
	Masked string `json:"masked"`
}

// maxLineLen caps how much of a line is examined. Minified bundles and
// embedded blobs are single enormous lines whose entropy is meaningless, and
// scanning them is pure cost.
const maxLineLen = 4096

// minEntropy is the Shannon entropy (bits/char) above which an opaque token is
// treated as a secret. Base64-encoded random data sits near 5.0-6.0; English
// prose and identifiers sit below 4.0.
const minEntropy = 4.0

// Scan examines the added lines of every file and returns the findings in
// file-then-line order.
func Scan(files []diff.File) []Finding {
	var out []Finding
	for _, f := range files {
		if isSkippedPath(f.Path) {
			continue
		}
		isEnv := envFileRe.MatchString(f.Path) && !envTemplateRe.MatchString(f.Path)

		// A newly committed .env is a finding in its own right: the fix is to
		// gitignore the file, regardless of what is currently inside it.
		if isEnv && f.IsNew {
			out = append(out, Finding{
				Path:   f.Path,
				Line:   0,
				Rule:   "env-file-committed",
				Tier:   int(TierFile),
				Reason: "a dotenv file is being committed; these hold real credentials and belong in .gitignore",
				Masked: f.Path,
			})
		}

		for _, ln := range f.Added {
			// Suppression is checked against the WHOLE line, before any
			// truncation: a marker sitting past maxLineLen would otherwise be
			// sliced off, leaving the user no way to silence the finding.
			if allowComment.MatchString(ln.Text) {
				continue
			}
			text := ln.Text
			if len(text) > maxLineLen {
				text = text[:maxLineLen]
			}
			if strings.ContainsRune(text, 0) {
				// Binary content that slipped past the path filter.
				break
			}
			if fs := scanLine(f.Path, ln.Num, text, isEnv); len(fs) > 0 {
				out = append(out, fs...)
			}
		}
	}
	return out
}

// scanLine returns at most one finding per line: the highest-confidence tier
// that matches. Reporting the same line three times teaches nothing.
func scanLine(path string, num int, text string, isEnv bool) []Finding {
	if f, ok := matchProvider(path, num, text); ok {
		return []Finding{f}
	}
	if f, ok := matchAssignment(path, num, text, isEnv); ok {
		return []Finding{f}
	}
	if f, ok := matchEntropy(path, num, text, isEnv); ok {
		return []Finding{f}
	}
	return nil
}

// matchProvider applies tier 1.
func matchProvider(path string, num int, text string) (Finding, bool) {
	for _, r := range providerRules {
		m := r.re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		secret := m[r.group]
		return Finding{
			Path:   path,
			Line:   num,
			Rule:   r.id,
			Tier:   int(TierProvider),
			Reason: r.reason,
			Masked: mask(secret),
		}, true
	}
	return Finding{}, false
}

// assign is one candidate KEY <sep> VALUE pair found on a line.
type assign struct {
	key    string
	val    string
	quoted bool
}

// assignments extracts the credential-shaped assignments from a line, from
// both the quoted-key and bare-key forms.
func assignments(text string) []assign {
	var out []assign

	add := func(m []string) {
		val := firstNonEmpty(m[2], m[3], m[4], m[5])
		if val == "" {
			return
		}
		out = append(out, assign{
			key:    m[1],
			val:    val,
			quoted: m[2] != "" || m[3] != "" || m[4] != "",
		})
	}

	for _, m := range assignmentQuotedKey.FindAllStringSubmatch(text, -1) {
		add(m)
	}

	// For bare keys, reject any whose preceding character is a quote: that is
	// an unterminated string literal, not an identifier, so the "key" is
	// message text. Without this, every `"secret-guard: %v"` log line in this
	// very codebase reports itself.
	for _, idx := range assignmentBareKey.FindAllStringSubmatchIndex(text, -1) {
		start := idx[2]
		if start > 0 {
			if c := text[start-1]; c == '"' || c == '\'' || c == '`' {
				continue
			}
		}
		m := make([]string, len(idx)/2)
		for i := range m {
			if idx[2*i] >= 0 {
				m[i] = text[idx[2*i]:idx[2*i+1]]
			}
		}
		add(m)
	}
	return out
}

// matchAssignment applies tier 2, plus the relaxed dotenv variant.
func matchAssignment(path string, num int, text string, isEnv bool) (Finding, bool) {
	for _, a := range assignments(text) {
		key, val, quoted := a.key, a.val, a.quoted

		keyIsSecretish := keyLooksSecret(key)
		if !keyIsSecretish && !isEnv {
			continue
		}
		if !plausibleSecret(val, quoted, keyIsSecretish) {
			continue
		}
		// `token = os.environ["TOKEN"]` reads a secret, it does not contain one.
		if !quoted && lookupRe.MatchString(text) {
			continue
		}

		if isEnv {
			// In a dotenv the key name is enough context when it is secret-ish;
			// otherwise fall back to the value looking genuinely random.
			if !keyIsSecretish && !(entropy(val) >= minEntropy && len(val) >= 24) {
				continue
			}
			return Finding{
				Path:   path,
				Line:   num,
				Rule:   "env-secret",
				Tier:   int(TierKeyword),
				Reason: fmt.Sprintf("dotenv entry %q holds a %d-character value", key, len(val)),
				Masked: mask(val),
			}, true
		}

		return Finding{
			Path:   path,
			Line:   num,
			Rule:   "hardcoded-secret",
			Tier:   int(TierKeyword),
			Reason: fmt.Sprintf("%q is assigned a literal %d-character value", key, len(val)),
			Masked: mask(val),
		}, true
	}
	return Finding{}, false
}

// matchEntropy applies tier 3. It only fires when the line itself mentions a
// credential-ish keyword, which is what keeps it off every commit hash and
// base64 asset in the repo.
func matchEntropy(path string, num int, text string, isEnv bool) (Finding, bool) {
	if !isEnv && !lineMentionsSecret(text) {
		return Finding{}, false
	}
	if lookupRe.MatchString(text) {
		return Finding{}, false
	}
	for _, cand := range entropyCandidate.FindAllString(text, -1) {
		if !plausibleSecret(cand, false, false) {
			continue
		}
		e := entropy(cand)
		if e < minEntropy {
			continue
		}
		return Finding{
			Path:   path,
			Line:   num,
			Rule:   "high-entropy-string",
			Tier:   int(TierEntropy),
			Reason: fmt.Sprintf("%d-character opaque string at %.1f bits/char entropy, on a line mentioning a credential", len(cand), e),
			Masked: mask(cand),
		}, true
	}
	return Finding{}, false
}

// plausibleSecret rejects values that are structurally secret-shaped but are
// placeholders, interpolations, URLs without credentials, or plain words.
func plausibleSecret(val string, quoted, keyIsSecretish bool) bool {
	v := strings.TrimSpace(val)
	min := 6
	if !quoted {
		// Bare tokens are noisier, so demand a little more length.
		min = 8
	}
	if len(v) < min {
		return false
	}
	if placeholderRe.MatchString(v) {
		return false
	}
	if strings.ContainsAny(v, "${}") && (strings.Contains(v, "${") || strings.Contains(v, "{{")) {
		return false
	}
	// A URL with no userinfo is a location, not a credential. Connection
	// strings that do carry a password are caught by tier 1 before this.
	if urlNoCreds.MatchString(v) {
		return false
	}
	// A value made only of letters and separators, with no digits, reads as a
	// word or identifier ("production", "secret-guard") rather than a key.
	//
	// This is skipped when the key itself is explicitly a credential: in
	// `DB_PASSWORD=supersecretpassword` the key already supplies the context,
	// and real passwords are very often plain lowercase words.
	if !keyIsSecretish && !strings.ContainsAny(v, "0123456789") && !strings.ContainsAny(v, "+/=!@#$%^&*") {
		letters := 0
		for _, r := range v {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '-' || r == '_' || r == '.' {
				letters++
			}
		}
		if letters == len(v) && entropy(v) < minEntropy {
			return false
		}
	}
	return true
}

// entropy is Shannon entropy in bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]float64
	n := 0
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
		n++
	}
	var e float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := c / float64(n)
		e -= p * math.Log2(p)
	}
	return e
}

// mask reduces a secret to a recognisable but unusable stub, so that neither
// terminal scrollback nor CI logs end up holding the credential.
func mask(secret string) string {
	s := strings.TrimSpace(secret)
	if len(s) < 12 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 8) + s[len(s)-4:]
}

func isSkippedPath(path string) bool {
	for _, re := range skipPaths {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
