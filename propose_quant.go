package main

// propose_quant.go handles the Kubernetes quantity math used by Propose so the
// arithmetic does not leak into the orchestration file.

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var (
	decimalRe = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)([KMGTPE]i?)$`)
	plainRe   = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)$`)
)

// decodeQuantity parses a Kubernetes resource quantity string into a raw byte
// count. Supported suffixes are the standard Ki/Mi/Gi/Ti/Pi/Ei set.
func decodeQuantity(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if m := decimalRe.FindStringSubmatch(s); m != nil {
		v, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, false
		}
		return v * multiplier(m[2]), true
	}
	if m := plainRe.FindStringSubmatch(s); m != nil {
		v, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

// scaleWithinBounds returns the smallest standard memory bump that fits the
// alert and stays below maxMultiplier of the current value.
func scaleWithinBounds(current, max float64) float64 {
	if current <= 0 || math.IsNaN(current) || math.IsInf(current, 0) {
		return current
	}
	candidates := []float64{current * 2, current * 4, current * 8}
	for _, c := range candidates {
		if c <= current*max {
			return c
		}
	}
	return current
}

func multiplier(unit string) float64 {
	switch unit {
	case "Ki":
		return 1024
	case "Mi":
		return 1024 * 1024
	case "Gi":
		return 1024 * 1024 * 1024
	case "Ti":
		return 1024 * 1024 * 1024 * 1024
	case "Pi":
		return 1024 * 1024 * 1024 * 1024 * 1024
	case "Ei":
		return 1024 * 1024 * 1024 * 1024 * 1024 * 1024
	case "K":
		return 1000
	case "M":
		return 1000 * 1000
	case "G":
		return 1000 * 1000 * 1000
	case "T":
		return 1000 * 1000 * 1000 * 1000
	}
	return 1
}

// encodeQuantity formats a byte count back into a Kubernetes memory string.
func encodeQuantity(v float64) string {
	steps := []struct {
		unit string
		size float64
	}{
		{"Ei", 1024 * 1024 * 1024 * 1024 * 1024 * 1024},
		{"Pi", 1024 * 1024 * 1024 * 1024 * 1024},
		{"Ti", 1024 * 1024 * 1024 * 1024},
		{"Gi", 1024 * 1024 * 1024},
		{"Mi", 1024 * 1024},
		{"Ki", 1024},
	}
	for _, s := range steps {
		if v >= s.size {
			return fmt.Sprintf("%s%s", strconv.FormatFloat(v/s.size, 'f', -1, 64), s.unit)
		}
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}
