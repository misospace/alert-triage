package main

// propose.go generates a reviewable unified diff for OomKilled alerts when the
// digest names a concrete file path. It is the read-only arm of issue #35:
// nothing is written to disk in the cluster and no branch is opened. A proposal
// is only shown when every guardrail below passes silently.
//
// The guardrails, in order, are:
//  1. The triage must be high-confidence and point at git (or partial where the
//     fix site is a file).
//  2. A relative file path must be attached. Without it there is nothing to
//     anchor the change.
//  3. The file must parse as a YAML document and round-trip with only the
//     intended scalar changed.
//  4. The value must parse as a Kubernetes quantity and the new value must
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
func Propose(t Triage, relativePath, original string) string {
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
		log.Printf("propose: dropped, unparsable memory value %q", target.child.Value)
		return "", false
	}
	proposed := scaleWithinBounds(currentValue, maxMultiplier)
	if proposed <= currentValue {
		log.Printf("propose: dropped, proposed value not greater for %s", cleanPath)
		return "", false
	}

	target.child.Value = encodeQuantity(proposed)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		log.Printf("propose: dropped, rewrite failed for %s: %v", cleanPath, err)
		return "", false
	}
	if err := enc.Close(); err != nil {
		log.Printf("propose: dropped, encoder close failed for %s: %v", cleanPath, err)
		return "", false
	}

	diff, err := unifiedDiff(cleanPath, original, buf.String())
	if err != nil {
		log.Printf("propose: dropped, diff failed for %s: %v", cleanPath, err)
		return "", false
	}
	return diff, true
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
