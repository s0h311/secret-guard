// Package report renders findings for humans and for machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/s0h311/secret-guard/internal/scan"
)

// Color codes are emitted only when the destination is a terminal, so piped
// and CI output stays clean.
const (
	cReset = "\033[0m"
	cBold  = "\033[1m"
	cDim   = "\033[2m"
	cRed   = "\033[31m"
	cYel   = "\033[33m"
	cCyan  = "\033[36m"
)

type palette struct{ reset, bold, dim, red, yellow, cyan string }

func paletteFor(w io.Writer) palette {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" {
		return palette{}
	}
	if info, err := f.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return palette{}
	}
	return palette{cReset, cBold, cDim, cRed, cYel, cCyan}
}

// JSON writes the findings as a stable machine-readable document.
func JSON(w io.Writer, findings []scan.Finding) error {
	type doc struct {
		Findings []scan.Finding `json:"findings"`
		Count    int            `json:"count"`
	}
	if findings == nil {
		findings = []scan.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc{Findings: findings, Count: len(findings)})
}

// Human writes the findings grouped by file.
func Human(w io.Writer, findings []scan.Finding, source string) {
	p := paletteFor(w)

	if len(findings) == 0 {
		fmt.Fprintf(w, "%s✓%s no secrets found in %s\n", p.cyan, p.reset, source)
		return
	}

	byFile := map[string][]scan.Finding{}
	var order []string
	for _, f := range findings {
		if _, seen := byFile[f.Path]; !seen {
			order = append(order, f.Path)
		}
		byFile[f.Path] = append(byFile[f.Path], f)
	}
	sort.Strings(order)

	for _, path := range order {
		fs := byFile[path]
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].Line < fs[j].Line })
		for _, f := range fs {
			loc := path
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", path, f.Line)
			}
			fmt.Fprintf(w, "\n%s%s%s\n", p.bold, loc, p.reset)
			fmt.Fprintf(w, "  %s⚠%s %s%s%s — %s\n", p.red, p.reset, p.yellow, f.Rule, p.reset, f.Reason)
			fmt.Fprintf(w, "    %svalue: %s  (tier %d, %s)%s\n", p.dim, f.Masked, f.Tier, scan.Tier(f.Tier), p.reset)
		}
	}

	noun := "secrets"
	if len(findings) == 1 {
		noun = "secret"
	}
	fmt.Fprintf(w, "\n%s%d suspected %s in %s%s\n", p.bold, len(findings), noun, source, p.reset)
	fmt.Fprintf(w, "%sFalse positive? append %ssecret-guard:allow%s%s to the line.%s\n",
		p.dim, p.reset+p.cyan, p.reset, p.dim, p.reset)
}
