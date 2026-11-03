package diff

import (
	"strings"
	"testing"
)

// Line numbers are worked out by hand from the hunk headers below, not
// recomputed the way the parser does it.
//
//	hunk 1 (@@ -1,3 +1,4 @@):  alpha=1  +beta=2   gamma=3  delta=4
//	hunk 2 (@@ -10,4 +11,6 @@): ten=11  -eleven consumes no new line,
//	                            +ELEVEN=12  +half=13  twelve=14  thirteen=15
const twoHunks = `diff --git a/config.yml b/config.yml
index 1111111..2222222 100644
--- a/config.yml
+++ b/config.yml
@@ -1,3 +1,4 @@
 alpha
+beta
 gamma
 delta
@@ -10,4 +11,6 @@
 ten
-eleven
+ELEVEN
+eleven-and-a-half
 twelve
 thirteen
`

func TestParseNumbersAddedLinesAcrossHunks(t *testing.T) {
	files, err := Parse(strings.NewReader(twoHunks))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if files[0].Path != "config.yml" {
		t.Errorf("path = %q, want %q", files[0].Path, "config.yml")
	}

	want := []Line{
		{Num: 2, Text: "beta"},
		{Num: 12, Text: "ELEVEN"},
		{Num: 13, Text: "eleven-and-a-half"},
	}
	got := files[0].Added
	if len(got) != len(want) {
		t.Fatalf("got %d added lines %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("added[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// Plain `diff -u` output has no "diff --git" line, so the "---" header is the
// only signal that one file has ended and the next has begun. An earlier
// version flushed only on "diff --git", so a multi-file patch collapsed into
// its last file and every added line was attributed to the wrong path.
const plainMultiFile = `diff -ru old/f1 new/f1
--- old/f1	2026-11-03 23:38:48.987812537 +0100
+++ new/f1	2026-11-03 23:38:48.987812537 +0100
@@ -1 +1,2 @@
 a
+first
diff -ru old/f2 new/f2
--- old/f2	2026-11-03 23:38:48.987812537 +0100
+++ new/f2	2026-11-03 23:38:48.987812537 +0100
@@ -1 +1,2 @@
 b
+second
`

func TestParseSeparatesFilesInAPlainDiffPatch(t *testing.T) {
	files, err := Parse(strings.NewReader(plainMultiFile))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2: %+v", len(files), files)
	}

	want := []struct {
		path string
		text string
	}{
		{"new/f1", "first"},
		{"new/f2", "second"},
	}
	for i, w := range want {
		if files[i].Path != w.path {
			t.Errorf("files[%d].Path = %q, want %q", i, files[i].Path, w.path)
		}
		if len(files[i].Added) != 1 {
			t.Fatalf("files[%d] has %d added lines, want 1", i, len(files[i].Added))
		}
		if got := files[i].Added[0]; got.Num != 2 || got.Text != w.text {
			t.Errorf("files[%d].Added[0] = %+v, want {Num:2 Text:%q}", i, got, w.text)
		}
	}
}

// A merge commit's combined diff has one prefix column per parent. " -AAA"
// means "removed relative to parent 2", not a context line, so it must not
// advance the post-image line counter.
//
//	@@@ -1,3 -1,3 +1,3 @@@ : "  line1"=1, "- BBB" and " -AAA" consume nothing,
//	                         "++resolved"=2, "  line3"=3
const combinedMerge = `diff --cc cfg.txt
index 39aa102,f80d8ff..5e777f6
--- a/cfg.txt
+++ b/cfg.txt
@@@ -1,3 -1,3 +1,3 @@@
  line1
- BBB
 -AAA
++resolved
  line3
`

func TestParseHandlesCombinedMergeDiffs(t *testing.T) {
	files, err := Parse(strings.NewReader(combinedMerge))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	want := []Line{{Num: 2, Text: "resolved"}}
	if got := files[0].Added; len(got) != 1 || got[0] != want[0] {
		t.Errorf("added = %+v, want %+v", got, want)
	}
}

// git quotes non-ASCII paths by default (core.quotePath), and leaving the
// quotes and octal escapes in place defeats every path-based rule, including
// the one that recognises a .env file.
func TestParseUnquotesNonASCIIPaths(t *testing.T) {
	const patch = `diff --git "a/caf\303\251.env" "b/caf\303\251.env"
new file mode 100644
--- /dev/null
+++ "b/caf\303\251.env"
@@ -0,0 +1 @@
+DB_PASSWORD=supersecretpassword
`
	files, err := Parse(strings.NewReader(patch))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if files[0].Path != "café.env" {
		t.Errorf("path = %q, want %q", files[0].Path, "café.env")
	}
	if !files[0].IsNew {
		t.Error("IsNew = false, want true for a file added from /dev/null")
	}
}
