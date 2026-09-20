package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

type sighting struct {
	Signature string    `json:"sig"`
	Title     string    `json:"title"`
	At        time.Time `json:"at"`
}

// History records every group the service has reported, so a digest can say
// whether an incident is novel or routine. It is deliberately a flat JSONL file
// rather than a database: the volume is a handful of records a day, and a file
// on the PVC survives restarts without a schema or a driver.
type History struct {
	mu      sync.Mutex
	path    string
	retain  time.Duration
	entries []sighting
}

func NewHistory(path string, retain time.Duration) (*History, error) {
	h := &History{path: path, retain: retain}
	if err := h.load(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *History) load() error {
	f, err := os.Open(h.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		// Any other open failure (corruption, permission denied, stale
		// mount) leaves the service still able to start: we begin with an
		// empty history and the on-disk file is left untouched so an
		// operator can inspect or move it aside.
		logf("history: open failed, starting empty: %v", err)
		return nil
	}
	defer f.Close()

	cutoff := time.Now().Add(-h.retain)
	// Stream the file line by line so a single corrupt/out-of-band line is
	// bounded in memory and the rest of the file never all sits in memory
	// at once. Each line is parsed as it is read; the oversized-line
	// handling (skip + log) lives in readHistoryLines.
	readHistoryLines(f, func(line []byte) bool {
		var s sighting
		// A truncated final line (killed mid-write) must not stop startup.
		if err := json.Unmarshal(line, &s); err != nil {
			return true
		}
		if s.At.After(cutoff) {
			h.entries = append(h.entries, s)
		}
		return true
	})
	return nil
}

// oversizedLineCap is the per-line size the loader is willing to retain.
// JSONL lines here are small; anything over this cap is a corrupt or
// out-of-band record that is skipped and logged.
const oversizedLineCap = 1024 * 1024

// oversizedLineSample is how much of an oversized record we keep around so
// the skip log can quote a fragment. The rest of the record is discarded
// through its newline, so a corrupt line is bounded in memory instead of
// fully buffered.
const oversizedLineSample = 512

// readHistoryLines streams a JSONL file line by line, calling parse with
// each line as it is read. parse returns false to stop the read early.
//
// A bufio.Scanner here used to end the whole read at the first line over
// its 1 MiB token cap (bufio.ErrTooLong), silently dropping every record
// after it; the next Compact then persisted the truncated snapshot, turning
// a transient read failure into permanent loss. ReadBytes has no such cap:
// an oversized line is skipped, logged once with its line number and the
// file offset where parsing resumed, and the read continues from the
// following line. The stream is read into parse one line at a time, so the
// file is never buffered whole, and an oversized record is retained only up
// to oversizedLineSample bytes while the remainder is discarded.
func readHistoryLines(f *os.File, parse func(line []byte) bool) {
	r := bufio.NewReaderSize(f, 64*1024)
	var (
		lineNo int
		// off tracks the absolute file offset of the start of the current
		// line. The loader runs over a freshly opened file, so the read
		// offset equals the file offset.
		off int64
	)
	for {
		line, lineStart, consumed, err := readHistoryLine(r, off)
		off = lineStart + int64(consumed)
		if len(line) > 0 {
			lineNo++
		}
		// Oversize is detected from how much of the stream the record
		// consumed, not from the (bounded) sample we retained. The check
		// runs before the EOF return on purpose: an unterminated oversized
		// final line (ReadBytes returns it with io.EOF) must be logged and
		// skipped exactly once, not appended.
		if int64(consumed) > oversizedLineCap {
			// Log once per oversized line: which line, the file offset the
			// skip happened at (lineStart), the record's length, and the
			// retained sample as a fragment so the operator can identify
			// the record.
			logf("history: skipping oversized line %d at file offset %d (%d bytes over %d cap, %q)",
				lineNo, lineStart, consumed-oversizedLineCap, oversizedLineCap, string(line))
		}
		if err != nil {
			if err != io.EOF {
				// Same policy as a bad open: surface once, keep running.
				logf("history: read failed, keeping what was read: %v", err)
			}
			return
		}
		if len(line) == 0 || int64(consumed) > oversizedLineCap {
			// Blank lines and oversized lines are skipped: the loader
			// resumes from the line after the one just skipped.
			continue
		}
		if !parse(line) {
			return
		}
	}
}

// readHistoryLine reads one line from r. startOff is the file offset where
// this line begins; it is returned so the caller can report the offset in
// the oversized-line log. consumed is the number of bytes taken from the
// stream for this line (including the terminator, when there is one) so
// the caller can advance its running offset correctly even when the
// oversized line's retained sample is shorter than the record it skipped.
//
// Lines within the cap are returned whole. An oversized line is retained
// only up to oversizedLineSample bytes and the remainder is discarded
// through its newline, so a corrupt/out-of-band record cannot occupy an
// unbounded amount of memory.
//
// The returned error is nil only when the line was newline-terminated.
// io.EOF means the line ended the file (a final line without a trailing
// newline).
func readHistoryLine(r *bufio.Reader, startOff int64) (line []byte, lineStart int64, consumed int, err error) {
	first, firstErr := r.ReadBytes('\n')
	if len(first) <= oversizedLineCap {
		// Normal path: the whole line was within the cap (or the file
		// ended short). Nothing to discard.
		return first, startOff, len(first), firstErr
	}
	// Oversized path: `first` alone already exceeds the cap.
	total := len(first)
	if bytes.IndexByte(first, '\n') >= 0 {
		// The terminating newline is already in `first`: the record is
		// complete. Retain only a sample.
		return tailSample(first, oversizedLineSample), startOff, total, nil
	}
	// The record continues past `first`. Retain the tail of what we have
	// and discard the rest as we stream through to the next newline.
	retained := tailSample(first, oversizedLineSample-1)
	for {
		next, nextErr := r.ReadBytes('\n')
		total += len(next)
		if bytes.IndexByte(next, '\n') >= 0 {
			// Newline found: the skipped record is complete.
			combined := make([]byte, 0, len(retained)+len(next))
			combined = append(append(combined, retained...), next...)
			return tailSample(combined, oversizedLineSample), startOff, total, nil
		}
		// No newline in this chunk: it is all part of the skipped record.
		retained = append(append([]byte(nil), retained...), next...)
		retained = tailSample(retained, oversizedLineSample-1)
		if nextErr != nil {
			// No newline and the read stopped: the record ran to end of
			// file (io.EOF) or the stream failed.
			return retained, startOff, total, nextErr
		}
	}
}

// tailSample returns the last n bytes of b (or all of b when it is no
// longer than n).
func tailSample(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}

// PriorSeen reports how many times the given signature has been recorded
// within the retention window. Unlike Record it does not mutate state or
// append to the on-disk log, so callers can inspect history before deciding
// whether to record.
func (h *History) PriorSeen(sig, title string) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	cutoff := time.Now().Add(-h.retain)
	n := 0
	for _, e := range h.entries {
		if !e.At.After(cutoff) {
			continue
		}
		if e.Signature == sig {
			n++
		}
	}
	return n
}

// Record stores a sighting and returns how many times this signature has been
// seen before, within the retention window and excluding the one just added.
func (h *History) Record(sig, title string, at time.Time) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	cutoff := at.Add(-h.retain)
	prior := 0
	kept := h.entries[:0]
	for _, e := range h.entries {
		if e.At.Before(cutoff) {
			continue
		}
		kept = append(kept, e)
		if e.Signature == sig {
			prior++
		}
	}
	h.entries = kept
	h.entries = append(h.entries, sighting{Signature: sig, Title: title, At: at})

	h.appendLine(sighting{Signature: sig, Title: title, At: at})
	return prior
}

// appendLine best-effort persists one record. Losing history is not worth
// failing a digest over, so errors are swallowed after being surfaced once.
func (h *History) appendLine(s sighting) {
	if h.path == "" {
		return
	}
	f, err := os.OpenFile(h.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		logf("history: append failed: %v", err)
		return
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(s); err != nil {
		logf("history: encode failed: %v", err)
	}
}

// compactRewriteDelay is a hook tests use to slow the temp-file write
// in Compact so they can observe PriorSeen and Record running
// concurrently with the rename. It is nil in production.
var compactRewriteDelay func()

// Compact rewrites the file without expired records. Called periodically
// so the file cannot grow without bound.
//
// The on-disk rewrite and rename run without holding h.mu so concurrent
// PriorSeen and Record callers do not stall on a slow filesystem; only
// the in-memory snapshot and the swap back into h.entries are guarded.
// A Record running mid-Compact appends to h.path (not the .tmp path), so
// the temp file is never half-written from another caller's view: the
// append either lands in the pre-rename file (lost on rename) or in the
// post-rename file (kept).
func (h *History) Compact() error {
	if h.path == "" {
		return nil
	}

	// Snapshot the in-window entries under the lock and release it. The
	// copy lives in a fresh backing array so a concurrent Record that
	// reuses h.entries' storage cannot trample the snapshot.
	h.mu.Lock()
	snapshotCutoff := time.Now().Add(-h.retain)
	snapshot := make([]sighting, 0, len(h.entries))
	for _, e := range h.entries {
		if e.At.After(snapshotCutoff) {
			snapshot = append(snapshot, e)
		}
	}
	h.mu.Unlock()

	// Write the snapshot to a temp file and rename it into place. No
	// lock is held during this window: a slow filesystem here cannot
	// stall the flush loop's PriorSeen/Record calls.
	tmp := h.path + ".tmp"
	if err := writeHistoryFile(tmp, snapshot); err != nil {
		return err
	}
	if compactRewriteDelay != nil {
		compactRewriteDelay()
	}
	if err := os.Rename(tmp, h.path); err != nil {
		return err
	}

	// Swap the in-memory state under the lock so PriorSeen and Record
	// see a consistent view. Any entries a concurrent Record added
	// during the rewrite are kept here (Record's appendLine also wrote
	// them to h.path, either pre-rename as a lost write or post-rename
	// as a kept write).
	h.mu.Lock()
	swapCutoff := time.Now().Add(-h.retain)
	pruned := h.entries[:0]
	for _, e := range h.entries {
		if e.At.After(swapCutoff) {
			pruned = append(pruned, e)
		}
	}
	h.entries = pruned
	h.mu.Unlock()
	return nil
}

// writeHistoryFile encodes entries as JSONL into path. The caller is
// responsible for the atomic rename into the final location.
func writeHistoryFile(path string, entries []sighting) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}
