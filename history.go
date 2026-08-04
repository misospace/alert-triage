package main

import (
	"bufio"
	"encoding/json"
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
		return err
	}
	defer f.Close()

	cutoff := time.Now().Add(-h.retain)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var s sighting
		// A truncated final line (killed mid-write) must not stop startup.
		if err := json.Unmarshal(line, &s); err != nil {
			continue
		}
		if s.At.After(cutoff) {
			h.entries = append(h.entries, s)
		}
	}
	return sc.Err()
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

// Compact rewrites the file without expired records. Called periodically so the
// file cannot grow without bound.
func (h *History) Compact() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.path == "" {
		return nil
	}

	cutoff := time.Now().Add(-h.retain)
	kept := h.entries[:0]
	for _, e := range h.entries {
		if e.At.After(cutoff) {
			kept = append(kept, e)
		}
	}
	h.entries = kept

	tmp := h.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, e := range h.entries {
		if err := enc.Encode(e); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, h.path)
}
