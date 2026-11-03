// Package diff parses unified diffs into the added lines of each file.
//
// Every input mode of secret-guard (working tree, a commit, a patch on stdin)
// is funnelled through this parser, so the scanner only ever sees added lines
// carrying their post-image line number.
package diff

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// Line is a single added line and its line number in the post-image file.
type Line struct {
	Num  int
	Text string
}

// File is one file touched by a diff, with only its added lines retained.
type File struct {
	Path  string
	Added []Line
	// IsNew reports whether the file did not exist before this change.
	IsNew bool
}

// maxTokenLen bounds a single input line. Minified bundles and embedded blobs
// are single enormous lines; give the scanner room so they are reported rather
// than failing the whole parse.
const maxTokenLen = 8 << 20

// Parse reads a unified diff and returns one File per added-to path. Files
// whose post-image is /dev/null (pure deletions) are skipped.
//
// Both git's own output and plain `diff -u` are accepted, as are combined
// diffs from merge commits (`@@@` headers with one prefix column per parent).
func Parse(r io.Reader) ([]File, error) {
	var (
		files   []File
		cur     *File
		lineNum int
		// width is the number of prefix columns in the current hunk: 1 for an
		// ordinary diff, N for a combined diff against N parents.
		width = 1
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxTokenLen)

	flush := func() {
		if cur != nil && cur.Path != "" && cur.Path != "/dev/null" {
			files = append(files, *cur)
		}
		cur = nil
	}

	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "diff --git "), strings.HasPrefix(line, "diff --cc "):
			flush()
			cur = &File{}
			width = 1

		case strings.HasPrefix(line, "new file mode"):
			if cur != nil {
				cur.IsNew = true
			}

		case strings.HasPrefix(line, "--- "):
			// A plain `diff -u` patch has no "diff --git" line, so this header
			// is where one file ends and the next begins.
			if cur != nil && cur.Path != "" {
				flush()
			}
			if cur == nil {
				cur = &File{}
				width = 1
			}
			if stripPrefix(strings.TrimPrefix(line, "--- ")) == "/dev/null" {
				cur.IsNew = true
			}

		case strings.HasPrefix(line, "+++ "):
			if cur == nil {
				cur = &File{}
				width = 1
			}
			cur.Path = stripPrefix(strings.TrimPrefix(line, "+++ "))

		case strings.HasPrefix(line, "@@"):
			if cur == nil {
				continue
			}
			// "@@" is an ordinary hunk, "@@@" a two-parent combined hunk, and
			// so on; the number of prefix columns is one less than the @ count.
			at := 0
			for at < len(line) && line[at] == '@' {
				at++
			}
			width = at - 1
			if width < 1 {
				width = 1
			}
			if n, ok := newStart(line); ok {
				lineNum = n
			}

		case strings.HasPrefix(line, "\\"):
			// "\ No newline at end of file" is not a content line.

		default:
			if cur == nil || cur.Path == "" || len(line) < width {
				continue
			}
			// In both ordinary and combined diffs, the prefix columns say what
			// happened to the line relative to each parent. A line is present
			// in the post-image unless some column removed it, and it is an
			// addition if some column added it.
			prefix, body := line[:width], line[width:]
			switch {
			case strings.ContainsRune(prefix, '-'):
				// Removed: consumes no post-image line number.
			case strings.ContainsRune(prefix, '+'):
				cur.Added = append(cur.Added, Line{Num: lineNum, Text: body})
				lineNum++
			default:
				lineNum++ // context
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return files, nil
}

// stripPrefix removes git's a/ or b/ path prefix, undoes git's path quoting,
// and drops any trailing tab-separated timestamp that plain `diff -u` appends.
func stripPrefix(s string) string {
	s = strings.TrimSpace(s)

	// With core.quotePath (the default), git renders a non-ASCII path as a
	// C-style quoted string: "b/caf\303\251.env". Unquote before anything
	// else, or the trailing quote defeats every path-based rule.
	if strings.HasPrefix(s, `"`) {
		if unquoted, err := strconv.Unquote(s); err == nil {
			s = unquoted
		}
	} else if i := strings.IndexByte(s, '\t'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}

	if s == "/dev/null" {
		return s
	}
	for _, p := range []string{"a/", "b/", "i/", "w/", "c/", "o/"} {
		if strings.HasPrefix(s, p) {
			return s[len(p):]
		}
	}
	return s
}

// newStart extracts the post-image starting line from a hunk header of the
// form "@@ -l,s +l,s @@", or "@@@ -l,s -l,s +l,s @@@" for a combined diff. In
// both cases the post-image is the one range introduced by '+'.
func newStart(hdr string) (int, bool) {
	i := strings.IndexByte(hdr, '+')
	if i < 0 {
		return 0, false
	}
	rest := hdr[i+1:]
	end := strings.IndexAny(rest, ", @")
	if end < 0 {
		end = len(rest)
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0, false
	}
	return n, true
}

// Synthetic builds a File from whole file contents, numbering every line as an
// addition. Used for untracked files, which no git diff reports.
func Synthetic(path string, content io.Reader) (File, error) {
	f := File{Path: path, IsNew: true}
	sc := bufio.NewScanner(content)
	sc.Buffer(make([]byte, 0, 64*1024), maxTokenLen)
	for n := 1; sc.Scan(); n++ {
		f.Added = append(f.Added, Line{Num: n, Text: sc.Text()})
	}
	return f, sc.Err()
}
