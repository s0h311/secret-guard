package scan

import (
	"regexp"
	"strings"
)

// rule is a tier-1 provider pattern: a shape specific enough that a match is
// almost certainly a real credential.
type rule struct {
	id     string
	reason string
	re     *regexp.Regexp
	// group is the submatch holding the secret itself, for masking. 0 means
	// the whole match.
	group int
}

var providerRules = []rule{
	{
		id:     "aws-access-key-id",
		reason: "AWS access key id (AKIA/ASIA followed by 16 uppercase chars)",
		re:     regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`),
		group:  1,
	},
	{
		id:     "github-token",
		reason: "GitHub personal access / app token (ghp_, gho_, ghs_, ghu_, ghr_ prefix)",
		re:     regexp.MustCompile(`\b(gh[poshu]_[A-Za-z0-9]{36,255})\b`),
		group:  1,
	},
	{
		id:     "slack-token",
		reason: "Slack API token (xox[baprs]- prefix)",
		re:     regexp.MustCompile(`\b(xox[baprs]-[A-Za-z0-9-]{10,})`),
		group:  1,
	},
	{
		id:     "stripe-secret-key",
		reason: "Stripe live secret key (sk_live_ prefix)",
		re:     regexp.MustCompile(`\b((?:sk|rk)_live_[A-Za-z0-9]{10,})\b`),
		group:  1,
	},
	{
		id:     "google-api-key",
		reason: "Google API key (AIza followed by 35 chars)",
		re:     regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})\b`),
		group:  1,
	},
	{
		id:     "openai-api-key",
		reason: "OpenAI API key (sk- or sk-proj- prefix)",
		re:     regexp.MustCompile(`\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b`),
		group:  1,
	},
	{
		id:     "private-key",
		reason: "PEM private key block header",
		re:     regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`),
		group:  0,
	},
	{
		id:     "connection-string-password",
		reason: "connection string with an inline password",
		re: regexp.MustCompile(
			`\b(?:postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|ftp|sftp|smtp|smtps|clickhouse)://` +
				`[^\s:/@"']+:([^\s:/@"']{3,})@`),
		group: 1,
	},
	{
		id:     "jwt",
		reason: "JSON Web Token (three base64url segments, alg header)",
		re:     regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b`),
		group:  1,
	},
}

// ambiguousAlone are secret words too short or too common to carry a LINE on
// their own: bare "pwd" is usually the shell command, "pass" is an English
// word, "creds" is a comment. They still count when they name a key, which is
// keyLooksSecret's job, not this one.
var ambiguousAlone = map[string]bool{"pwd": true, "pass": true, "creds": true, "key": true}

// lineMentionsSecret reports whether a LINE talks about a credential at all.
// It gates tier 3, whose job is to catch opaque blobs that are not in
// assignment form.
//
// The check is word-aware for the same reason key matching is: a substring
// test on "pwd" fires on any three characters that happen to spell it, which
// on 200k lines of ordinary text is hundreds of false positives.
func lineMentionsSecret(line string) bool {
	words := splitIdentifier(line)
	for i, w := range words {
		if secretWords[w] && !ambiguousAlone[w] {
			return true
		}
		// Check adjacent pairs too, so that "api_key", "X-Api-Key" and
		// "apiKey" all gate the same way. Comparing each word alone would
		// never match the joined forms in secretWordPairs.
		if i+1 < len(words) {
			joined := w + words[i+1]
			for _, pair := range secretWordPairs {
				if joined == pair {
					return true
				}
			}
		}
	}
	return false
}

// value is the right-hand side of an assignment: a quoted literal or a bare
// token. Quoted alternatives come first so a quoted value wins.
const valuePattern = `(?:"([^"]*)"|'([^']*)'|` + "`([^`]*)`" + `|([^\s,;{}()\[\]]+))`

// assignmentBareKey matches KEY <sep> VALUE with an unquoted key, as in Go,
// YAML, TOML, ini and dotenv.
//
// A bare key whose preceding character is a quote is rejected by the caller.
// That is what distinguishes a JSON key from a format string: in
// `"password": "x"` the quote closes before the separator, whereas in
// `fmt.Fprintf(w, "secret-guard: %v", err)` the quote is still open, and the
// "key" is really the start of a message.
var assignmentBareKey = regexp.MustCompile(
	`(?i)([A-Za-z_][A-Za-z0-9_\-\.\[\]]*)\s*(?::=|=>|[:=])\s*` + valuePattern)

// assignmentQuotedKey matches a quoted key, as in JSON and quoted YAML.
var assignmentQuotedKey = regexp.MustCompile(
	`(?i)["']([A-Za-z_][A-Za-z0-9_\-\.]*)["']\s*(?::=|=>|[:=])\s*` + valuePattern)

// placeholders are values that look like secrets structurally but are stand-ins
// a developer is expected to replace.
var placeholderRe = regexp.MustCompile(`(?i)^(?:` +
	`x+|\*+|\.+|-+|_+|0+|` +
	`change[_\-]?me|changeit|your[_\-]?.*|my[_\-]?.*|some[_\-]?.*|` +
	`example|sample|dummy|placeholder|dummy[_\-]?.*|test|testing|` +
	`todo|tbd|fixme|fill[_\-]?me[_\-]?in|replace[_\-]?me|` +
	`secret|password|passwd|pwd|token|apikey|api[_\-]?key|value|` +
	`none|null|nil|undefined|empty|false|true|` +
	`string|str|text|varchar|boolean|bool|integer|int|number|float|` +
	`required|optional|yes|no|on|off|enabled|disabled|` +
	`redacted|hidden|masked|removed|omitted|sanitized|` +
	`\<.*\>|\{\{.*\}\}|\$\{.*\}|\$\(.*\)|%\(.*\)s|:.*:|@.*@` +
	`)$`)

// lookups are expressions that read a secret from somewhere else; the literal
// on the line is a variable name, not the secret.
var lookupRe = regexp.MustCompile(`(?i)\b(` +
	`os\.environ|os\.getenv|getenv|process\.env|import\.meta\.env|ENV\[|` +
	`config\.|conf\.|settings\.|secrets\.|vault|keyring|keychain|` +
	`System\.getenv|Environment\.GetEnvironmentVariable|std::env)`)

// skipPaths are file shapes whose high-entropy content is noise: generated
// lockfiles, minified bundles, sourcemaps and binaries.
var skipPaths = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|npm-shrinkwrap\.json)$`),
	regexp.MustCompile(`(?i)(^|/)(go\.sum|Cargo\.lock|poetry\.lock|Pipfile\.lock|composer\.lock|Gemfile\.lock|flake\.lock|bun\.lockb?)$`),
	regexp.MustCompile(`(?i)\.(min\.js|min\.css|map)$`),
	regexp.MustCompile(`(?i)\.(png|jpe?g|gif|bmp|ico|webp|svg|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|o|a|so|dylib|dll|exe|bin|wasm|woff2?|ttf|eot|otf|mp[34]|mov|avi|mkv|parquet|avro|db|sqlite3?)$`),
	regexp.MustCompile(`(?i)(^|/)(vendor|node_modules|\.git|dist|build|target|__pycache__)/`),
}

// envFile matches dotenv-shaped paths. Example/template variants are excluded
// because they are meant to be committed.
var (
	envFileRe     = regexp.MustCompile(`(?i)(^|/)(\.env(\..+)?|.+\.env|\.envrc)$`)
	envTemplateRe = regexp.MustCompile(`(?i)\.(example|sample|template|dist|tpl|tmpl|default)$|(^|/)\.env\.(example|sample|template|dist|defaults?)$`)
)

// allowComment is the inline suppression marker. Deliberately comment-syntax
// agnostic: anything containing the token suppresses that line.
var allowComment = regexp.MustCompile(`secret-guard:\s*allow`)

// entropyCandidate matches a long opaque token worth scoring for entropy.
// entropyCandidate matches a long opaque token worth scoring for entropy.
//
// '=' is allowed only as trailing base64 padding, never inside the token,
// otherwise `DB_PASSWORD=your_password_here` matches as one long blob. '/' and
// '.' are excluded so that paths and import specifiers
// ("github.com/s0h311/secret-guard/internal/diff") break into short segments
// instead of scoring as one high-entropy string. The cost is that a standard
// base64 secret containing '/' is split; base64url secrets, which use '-' and
// '_', are unaffected.
var entropyCandidate = regexp.MustCompile(`[A-Za-z0-9+_\-]{24,}={0,2}`)

// urlNoCreds matches a URL that carries no userinfo, so it is not a leak.
// The marker below is this tool suppressing a finding in its own source: the
// key contains "creds", so tier 2 reads the regex as an assigned literal.
var urlNoCreds = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://[^@\s]*$`) // secret-guard:allow regex pattern, not a credential

// secretWords are identifier words that, on their own, mark a key as holding a
// credential. Matching whole words rather than substrings is what lets "pass"
// catch `dbPass` without also catching `bypass` or `compass`.
var secretWords = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "pass": true,
	"passphrase": true, "secret": true, "token": true, "credential": true,
	"credentials": true, "creds": true, "apikey": true, "privkey": true,
}

// secretWordPairs are concatenations that only read as a credential in
// combination, so that a bare "key" or "auth" does not trip on `public_key`
// or `auth_url`.
var secretWordPairs = []string{
	"apikey", "accesskey", "secretkey", "privatekey", "signingkey",
	"encryptionkey", "masterkey", "consumerkey", "consumersecret",
	"authtoken", "accesstoken", "refreshtoken", "sessiontoken", "bearertoken",
	"clientsecret", "clientkey", "apisecret", "apitoken", "authkey",
}

// keyLooksSecret reports whether an assignment's key names a credential.
func keyLooksSecret(key string) bool {
	words := splitIdentifier(key)
	for _, w := range words {
		if secretWords[w] {
			return true
		}
	}
	joined := strings.Join(words, "")
	for _, pair := range secretWordPairs {
		if strings.Contains(joined, pair) {
			return true
		}
	}
	return false
}

// splitIdentifier breaks an identifier into lowercased words, splitting on
// non-alphanumeric separators and on lower-to-upper transitions so that
// snake_case, kebab-case, SCREAMING_CASE and camelCase all normalise the same.
func splitIdentifier(s string) []string {
	var words []string
	var cur []rune
	rs := []rune(s)
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = nil
		}
	}
	for i, r := range rs {
		switch {
		case !isAlnum(r):
			flush()
		case i > 0 && isUpper(r) && isLower(rs[i-1]):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return words
}

func isAlnum(r rune) bool { return isUpper(r) || isLower(r) || (r >= '0' && r <= '9') }
func isUpper(r rune) bool { return r >= 'A' && r <= 'Z' }
func isLower(r rune) bool { return r >= 'a' && r <= 'z' }
