package scan

import (
	"strings"
	"testing"

	"github.com/s0h311/secret-guard/internal/diff"
)

func file(path string, lines ...string) diff.File {
	f := diff.File{Path: path}
	for i, l := range lines {
		f.Added = append(f.Added, diff.Line{Num: i + 1, Text: l})
	}
	return f
}

func TestScanTiers(t *testing.T) {
	cases := []struct {
		name string
		file diff.File
		// wantRule is the rule id expected on the first finding; empty means
		// the input must produce no findings at all.
		wantRule string
	}{
		// --- tier 1: provider patterns -------------------------------------
		{"aws access key", file("infra.tf", `access_key = "AKIAIOSFODNN7EXAMPLE"`), "aws-access-key-id"},
		{"github pat", file("ci.sh", `TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789`), "github-token"},
		{"slack bot token", file("app.py", `slack = "xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx"`), "slack-token"},
		{"stripe live key", file("pay.js", `const k = "sk_live_51H8xQ2eZvKYlo2CkIhPzXvB7mTyR4dLg"`), "stripe-secret-key"},
		{"google api key", file("maps.js", `key: "AIzaSyB7mTyR4dLgF6hCaE9uZnkJ8sNq2wPzXvB"`), "google-api-key"},
		{"private key block", file("id_rsa", `-----BEGIN RSA PRIVATE KEY-----`), "private-key"},
		{"db uri with password", file("app.go", `dsn := "postgres://admin:s3cr3tpw@db.internal:5432/app"`), "connection-string-password"},

		// --- tier 2: keyword assignment ------------------------------------
		{"quoted password", file("conf.rb", `password = "hunter2hunter2"`), "hardcoded-secret"},
		{"unquoted yaml password", file("db.yml", `  db_password: sup3rs3cretpw`), "hardcoded-secret"},
		// camelCase keys split the same way as snake_case ones.
		{"camelcase pass key", file("conf.go", `dbPass = "pr0dpassw0rd!"`), "hardcoded-secret"},
		// "pwd" is too ambiguous to carry a line on its own, but still counts
		// as a key name.
		{"pwd as a key", file("conf.go", `dbPwd = "pr0dpassw0rd!"`), "hardcoded-secret"},

		// --- tier 3: entropy, context gated --------------------------------
		// Not in assignment form, so tier 2 cannot see it; the keyword "token"
		// elsewhere on the line is what unlocks the entropy check.
		{"high entropy, not an assignment", file("client.go",
			`req.Header.Set("Authorization", "token kJ8sNq2wPzXvB7mTyR4dLgF6hCaE9uZn")`), "high-entropy-string"},

		// --- .env as a high-signal file class ------------------------------
		{"env secret-ish key", file(".env", `DB_PASSWORD=supersecretpassword`), "env-secret"},
		{"env high entropy value", file(".env", `BLOB=kJ8sNq2wPzXvB7mTyR4dLgF6hCaE9uZn`), "env-secret"},

		// --- negatives: these must stay silent -----------------------------
		{"placeholder xxx", file("conf.rb", `password = "xxx"`), ""},
		{"placeholder changeme", file("conf.rb", `password = "changeme"`), ""},
		{"shell interpolation", file("conf.rb", `api_key = "${API_KEY}"`), ""},
		{"redacted marker", file("conf.rb", `secret = "<redacted>"`), ""},
		{"env lookup not literal", file("app.py", `token = os.environ["TOKEN"]`), ""},
		{"type annotation", file("schema.yml", `  password: string`), ""},
		// "pass" is matched as a whole word, so these keys must not trip it.
		{"bypass is not pass", file("conf.go", `bypass = "someLongValue123"`), ""},
		{"public key is not a secret", file("conf.go", `public_key = "someLongValue123"`), ""},
		// Bare "pwd" is the shell command, so it must not unlock the entropy
		// tier for an unrelated high-entropy token on the same line.
		{"pwd as a shell command", file("build.sh",
			`echo "$(pwd)/kJ8sNq2wPzXvB7mTyR4dLgF6hCaE9uZn"`), ""},
		{"too short", file("conf.rb", `password = "abc"`), ""},
		{"allow comment", file("conf.rb", `password = "hunter2hunter2" # secret-guard:allow test fixture`), ""},
		{"lockfile is skipped", file("package-lock.json", `"integrity": "sha512-kJ8sNq2wPzXvB7mTyR4dLgF6hCaE9uZnQ2wPzXvB7mTyR4dLgF6hCaE9uZn=="`), ""},
		{"minified bundle skipped", file("dist/app.min.js", `var k="AKIAIOSFODNN7EXAMPLE"`), ""},
		{"env example is a template", file(".env.example", `DB_PASSWORD=your_password_here`), ""},
		{"env plain word value", file(".env", `APP_NAME=secret-guard`), ""},
		{"env url without creds", file(".env", `API_URL=https://api.example.com/v1`), ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Scan([]diff.File{tc.file})
			if tc.wantRule == "" {
				if len(got) != 0 {
					t.Fatalf("want no findings, got %d: %+v", len(got), got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("want rule %q, got no findings", tc.wantRule)
			}
			if got[0].Rule != tc.wantRule {
				t.Errorf("rule = %q, want %q (reason: %s)", got[0].Rule, tc.wantRule, got[0].Reason)
			}
			if got[0].Line != 1 {
				t.Errorf("line = %d, want 1", got[0].Line)
			}
			if got[0].Reason == "" {
				t.Error("reason must not be empty")
			}
		})
	}
}

// A newly added .env is itself the finding, independent of its contents.
func TestScanFlagsNewlyAddedEnvFile(t *testing.T) {
	f := file(".env", `APP_NAME=secret-guard`)
	f.IsNew = true

	got := Scan([]diff.File{f})
	if len(got) == 0 {
		t.Fatal("want a file-level finding for a newly added .env")
	}
	if got[0].Rule != "env-file-committed" {
		t.Errorf("rule = %q, want %q", got[0].Rule, "env-file-committed")
	}
	if got[0].Line != 0 {
		t.Errorf("line = %d, want 0 for a file-level finding", got[0].Line)
	}
}

// The scanner must never print the secret it found.
func TestScanMasksTheSecret(t *testing.T) {
	got := Scan([]diff.File{file("infra.tf", `access_key = "AKIAIOSFODNN7EXAMPLE"`)})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if strings.Contains(got[0].Masked, "IOSFODNN7") {
		t.Errorf("masked value %q still exposes the secret", got[0].Masked)
	}
	if !strings.Contains(got[0].Masked, "*") {
		t.Errorf("masked value %q has no mask characters", got[0].Masked)
	}
}
