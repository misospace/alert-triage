package main

// propose.go generates a reviewable unified diff for OomKilled alerts when the
// digest names a concrete file path. It is the read-only arm of issue #35:
// nothing is written to disk in the cluster and no branch is opened. A proposal
// is only shown when every guardrail below passes silently.
//
// The guardrails, in order, are:
//  1. The group's alerts must name a memory-pressure fault (an OOMKilled /
//     ContainerOOMKilled alert, or a terminated-reason label of OOMKilled).
//     A memory bump is defensible only because a container was killed for
//     memory; on any other alert the same triage is guesswork dressed as a fix.
//  2. The triage must be high-confidence and point at git (or partial where the
//     fix site is a file).
//  3. A relative file path must be attached. Without it there is nothing to
//     anchor the change.
//  4. The file must parse as a YAML document, and the new value must be
//     replaceable at exactly the position the parser recorded for the scalar,
//     so every other byte of the file — indentation, quoting, comments,
//     further documents — is preserved as-is. Re-encoding the parsed document
//     instead normalises unrelated formatting (a four-space manifest comes
//     back two-space indented), and a diff carrying only the first changed
//     region then drops the memory change while still applying cleanly,
//     which is how #274 reached a purported memory fix with no memory
//     increase. If the emitted patch would not reproduce the intended
//     content under the write arm's own applier, no proposal is shown.
//  5. The value must parse as a Kubernetes quantity and the new value must
//     stay within a bounded multiplier of the old one.
//
// An empty return means no proposal is warranted; the report layer renders the
// result under `proposed_diff` only when it is non-empty.

import (
	"bytes"
	"fmt"
	"log"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// maxMultiplier caps how large a proposed bump can be.
const maxMultiplier = 8.0

// Propose returns a unified diff or "" when no proposal should be shown.
// alerts are the group's alerts: the alert-type gate (guardrail 1) runs
// before any file content is touched, so a non-memory-pressure alert is
// refused without a YAML walk.
func Propose(alerts []Alert, t Triage, relativePath, original string) string {
	if !memoryPressureAlerts(alerts) {
		log.Printf("propose: dropped, no memory-pressure alert in group")
		return ""
	}
	if !proposalEligible(t) {
		log.Printf("propose: dropped, confidence=%q fix_location=%q", t.Confidence, t.FixLocation)
		return ""
	}
	if strings.TrimSpace(relativePath) == "" {
		log.Printf("propose: dropped, no path attached to digest")
		return ""
	}
	if strings.TrimSpace(original) == "" {
		log.Printf("propose: dropped, empty file contents for %s", relativePath)
		return ""
	}

	patch, ok := buildMemoryPatch(relativePath, original)
	if !ok {
		return ""
	}
	return patch
}

func proposalEligible(t Triage) bool {
	if t.FixLocation != "git" && t.FixLocation != "partial" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(t.Confidence), "high")
}

// memoryPressureAlerts reports whether the group carries a memory-pressure
// alert, i.e. the one kind of fault for which raising a memory limit is a
// defensible fix: an alert named OOMKilled or ContainerOOMKilled, or a
// kube-state-metrics style rule carrying a
// kube_pod_container_status[_last]_terminated_reason label of OOMKilled.
// A group that fired for anything else — node health, image pulls, probes,
// networking — is refused before any YAML walk.
func memoryPressureAlerts(alerts []Alert) bool {
	terminatedReason := func(v string) bool {
		return strings.EqualFold(strings.TrimSpace(v), "OOMKilled")
	}
	for _, a := range alerts {
		name := a.name()
		if name == "OOMKilled" || name == "ContainerOOMKilled" {
			return true
		}
		for _, k := range []string{
			"kube_pod_container_status_terminated_reason",
			"kube_pod_container_status_last_terminated_reason",
		} {
			if terminatedReason(a.Labels[k]) {
				return true
			}
		}
	}
	return false
}

// memoryTarget pins the parent block that owns the memory scalar.
type memoryTarget struct {
	parent    *yaml.Node // the limits/requests mapping node
	child     *yaml.Node // the memory scalar node we will rewrite
	container string
}

// buildMemoryPatch parses the file once, lifts the right container's memory
// field, raises it within bounds, and emits a unified diff.
func buildMemoryPatch(relPath, original string) (string, bool) {
	cleanPath := path.Clean(relPath)
	if cleanPath == "." || cleanPath == "/" || strings.HasPrefix(cleanPath, "..") {
		log.Printf("propose: dropped, unsafe path %q", relPath)
		return "", false
	}

	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(original), &doc); err != nil {
		log.Printf("propose: dropped, yaml parse failed for %s: %v", cleanPath, err)
		return "", false
	}

	target := locateMemoryTarget(&doc)
	if target == nil {
		log.Printf("propose: dropped, no memory field in %s", cleanPath)
		return "", false
	}

	currentValue, ok := decodeQuantity(target.child.Value)
	if !ok {
		// "Unusable" covers a value that does not parse and one whose
		// suffix overflows float64 (#204): neither is a byte count the
		// guardrails below can reason about.
		log.Printf("propose: dropped, unusable memory value %q", target.child.Value)
		return "", false
	}
	proposed := scaleWithinBounds(currentValue, maxMultiplier)
	if proposed <= currentValue {
		log.Printf("propose: dropped, proposed value not greater for %s", cleanPath)
		return "", false
	}
	encoded, ok := encodeQuantity(proposed)
	if !ok {
		log.Printf("propose: dropped, proposed value not encodable for %s", cleanPath)
		return "", false
	}

	patched, ok := replaceScalarValue(original, target.child.Line, target.child.Column, target.child.Value, encoded)
	if !ok {
		// The scalar did not reappear in the source text exactly as it
		// parsed (a tag, a block scalar, an escape, a byte at the recorded
		// column that is not the value): refuse rather than fall back to a
		// re-encode, whose scattered formatting differences the single-hunk
		// diff cannot represent (#274).
		log.Printf("propose: dropped, memory scalar at %d:%d is not replaceable in place for %s",
			target.child.Line, target.child.Column, cleanPath)
		return "", false
	}
	if !patchCarriesMemoryChange(patched, encoded, target.container) {
		log.Printf("propose: dropped, patched content does not carry the intended change for %s", cleanPath)
		return "", false
	}

	diff, err := unifiedDiff(cleanPath, original, patched)
	if err != nil {
		log.Printf("propose: dropped, diff failed for %s: %v", cleanPath, err)
		return "", false
	}
	// The write arm commits applyDiff(content, diff), not the content verified
	// above. Prove the emitted patch reproduces exactly that content under
	// the same applier before anyone is allowed to ship it.
	if applied, ok := applyDiff(original, diff); !ok || applied != patched {
		log.Printf("propose: dropped, emitted patch does not reproduce patched content for %s", cleanPath)
		return "", false
	}
	return diff, true
}

// replaceScalarValue rewrites one scalar token in the source text at the
// line:column the parser recorded for it, returning the new content. This is
// why the patch can promise "everything except the memory value is untouched"
// even for files whose formatting yaml.v3 would not reproduce: no re-encode
// happens, so nothing outside the token can move. Anything that cannot be
// confined to the token itself — a tag between column and value, a block
// scalar, an escaped quote, trailing text that is not a comment or flow
// terminator — fails closed, because a diff we cannot prove is exactly the
// intended change is worse than no diff.
func replaceScalarValue(original string, line, column int, oldValue, newValue string) (string, bool) {
	if oldValue == "" || newValue == "" {
		return "", false
	}
	lines := strings.Split(original, "\n")
	if line < 1 || line > len(lines) {
		return "", false
	}
	text := lines[line-1]
	start := column - 1
	if start < 0 || start >= len(text) {
		return "", false
	}
	rest0 := text[start:]

	var token, rest string
	switch {
	case strings.HasPrefix(rest0, oldValue):
		token, rest = newValue, rest0[len(oldValue):]
	case strings.HasPrefix(rest0, `"`), strings.HasPrefix(rest0, "'"):
		quote := rest0[0]
		end := closingQuote(rest0, quote)
		if end < 0 {
			return "", false
		}
		inner := rest0[1 : end-1]
		if quote == '"' && strings.Contains(inner, `\`) {
			// An escaped double quote decodes to text we cannot re-derive
			// token-safe from the raw bytes.
			return "", false
		}
		if quote == '\'' {
			inner = strings.ReplaceAll(inner, "''", "'")
		}
		if inner != oldValue {
			return "", false
		}
		token, rest = string(quote)+newValue+string(quote), rest0[end:]
	default:
		return "", false
	}
	if !scalarTokenEndIsBoundary(rest) {
		return "", false
	}

	lines[line-1] = text[:start] + token + rest
	return strings.Join(lines, "\n"), true
}

// closingQuote returns the index just past the matching close quote of a
// quoted scalar starting at rest[0], or -1 when no closing quote exists on
// that line.
func closingQuote(rest string, quote byte) int {
	for i := 1; i < len(rest); i++ {
		switch {
		case quote == '"' && rest[i] == '\\':
			i++ // an escaped character cannot close the quote
		case rest[i] == quote:
			if quote == '\'' && i+1 < len(rest) && rest[i+1] == '\'' {
				i++ // a doubled '' is an escaped quote, not the close
				continue
			}
			return i + 1
		}
	}
	return -1
}

// scalarTokenEndIsBoundary reports whether only whitespace, a comment, a flow
// collection terminator, or the carriage return of a CRLF line follows the
// value token on its line — never more scalar text, which would mean the
// recorded column did not line up with the value as parsed.
func scalarTokenEndIsBoundary(rest string) bool {
	trimmed := strings.TrimLeft(rest, " \t")
	if trimmed == "" {
		return true
	}
	switch trimmed[0] {
	case '#', ',', ']', '}', '\r':
		return true
	}
	return false
}

// patchCarriesMemoryChange re-parses the patched content and requires the
// memory target to hold the new value in the same container, so the change
// provably landed where it was intended and the document still parses.
func patchCarriesMemoryChange(patched, encoded, container string) bool {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(patched), &doc); err != nil {
		return false
	}
	target := locateMemoryTarget(&doc)
	return target != nil && target.child.Value == encoded && target.container == container
}

// rootNode strips the DocumentNode wrapper that yaml.Unmarshal produces.
func rootNode(doc *yaml.Node) *yaml.Node {
	if doc == nil {
		return nil
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0]
	}
	return doc
}

func locateMemoryTarget(doc *yaml.Node) *memoryTarget {
	root := rootNode(doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil
	}
	containers := findContainers(root)
	for _, c := range containers {
		name := scalarOf(c, "name")
		res := childByKey(c, "resources")
		if res == nil || res.Kind != yaml.MappingNode {
			continue
		}
		for _, sub := range []string{"limits", "requests"} {
			block := childByKey(res, sub)
			if block == nil || block.Kind != yaml.MappingNode {
				continue
			}
			mem := childByKey(block, "memory")
			if mem == nil || mem.Kind != yaml.ScalarNode {
				continue
			}
			return &memoryTarget{parent: block, child: mem, container: name}
		}
	}
	return nil
}

// findContainers walks spec.template.spec.containers — the only manifest
// shape this proposer's scope covers. Spec.template can itself be a scalar
// reference; we ignore those.
func findContainers(root *yaml.Node) []*yaml.Node {
	spec := childByKey(root, "spec")
	if spec == nil {
		return nil
	}
	tpl := childByKey(spec, "template")
	if tpl == nil || tpl.Kind != yaml.MappingNode {
		return nil
	}
	tplSpec := childByKey(tpl, "spec")
	if tplSpec == nil || tplSpec.Kind != yaml.MappingNode {
		return nil
	}
	list := childByKey(tplSpec, "containers")
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil
	}
	return list.Content
}

// childByKey returns the value node for a mapping key, or nil.
func childByKey(m *yaml.Node, name string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == name {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalarOf(m *yaml.Node, name string) string {
	n := childByKey(m, name)
	if n == nil {
		return ""
	}
	return n.Value
}

// unifiedDiff emits a minimal hunk around the actual change. Everything else
// stays identical, which keeps the patch tight and review-friendly.
func unifiedDiff(relPath, original, patched string) (string, error) {
	oLines := splitLines(original)
	pLines := splitLines(patched)

	oi, pi := firstDiff(oLines, pLines)
	if oi < 0 {
		return "", fmt.Errorf("round-trip modified content without an intended change")
	}
	aligned := alignHunks(oLines, pLines, oi, pi)

	hunkOld := oLines[aligned.oh0 : aligned.oh1+1]
	hunkNew := pLines[aligned.nh0 : aligned.nh1+1]

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "--- a/%s\n", relPath)
	fmt.Fprintf(&buf, "+++ b/%s\n", relPath)
	fmt.Fprintf(&buf, "@@ -%d,%d +%d,%d @@\n",
		aligned.oh0+1, len(hunkOld),
		aligned.nh0+1, len(hunkNew))
	for _, l := range hunkOld {
		fmt.Fprintf(&buf, "-%s\n", l)
	}
	for _, l := range hunkNew {
		fmt.Fprintf(&buf, "+%s\n", l)
	}
	return buf.String(), nil
}

// alignHunks widens the changed region with bounded context lines on each side.
type hunk struct{ oh0, oh1, nh0, nh1 int }

func alignHunks(a, b []string, oi, pi int) hunk {
	const context = 5
	oh0, nh0 := oi, pi
	for k := 0; k < context && oh0 > 0 && nh0 > 0 && a[oh0-1] == b[nh0-1]; k++ {
		oh0--
		nh0--
	}
	oh1, nh1 := oi, pi
	for k := 0; k < context && oh1+1 < len(a) && nh1+1 < len(b) && a[oh1+1] == b[nh1+1]; k++ {
		oh1++
		nh1++
	}
	return hunk{oh0: oh0, oh1: oh1, nh0: nh0, nh1: nh1}
}

func splitLines(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}

func firstDiff(a, b []string) (int, int) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i, i
		}
	}
	if len(a) != len(b) {
		return n, n
	}
	return -1, -1
}
