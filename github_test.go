package main

import (
	"fmt"
	"testing"
	"time"
)

func TestNewGitHubUnset(t *testing.T) {
	cfg := &Config{}
	if got := newGitHub(cfg); got != nil {
		t.Fatalf("newGitHub with no env should return nil, got %#v", got)
	}
	cfg.GitHubRepo = "owner/repo"
	if got := newGitHub(cfg); got != nil {
		t.Fatalf("newGitHub with token unset should return nil, got %#v", got)
	}
	cfg.GitHubToken = "tok"
	got := newGitHub(cfg)
	if got == nil {
		t.Fatalf("newGitHub with both env vars set should return a client")
	}
	if got.repo != "owner/repo" || got.token != "tok" {
		t.Fatalf("client misconfigured: %#v", got)
	}
}

func TestShouldCommentInterval(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		iss  *ghIssue
		want bool
	}{
		{
			name: "fresh open, no recent comment, no severity match",
			iss:  &ghIssue{CreatedAt: now.Add(-5 * time.Minute), UpdatedAt: now.Add(-5 * time.Minute)},
			want: true, // first re-fire always comments
		},
		{
			name: "comment 1 minute ago is suppressed",
			iss:  &ghIssue{CreatedAt: now.Add(-1 * time.Hour), UpdatedAt: now.Add(-1 * time.Minute), Comments: 1},
			want: false,
		},
		{
			name: "comment 13h ago passes",
			iss:  &ghIssue{CreatedAt: now.Add(-2 * 24 * time.Hour), UpdatedAt: now.Add(-13 * time.Hour), Comments: 2},
			want: true,
		},
	}
	r := Report{Group: Group{Key: "KubeJobFailed"}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldComment(c.iss, r, 12*time.Hour); got != c.want {
				t.Fatalf("want %v got %v", c.want, got)
			}
		})
	}
}

func TestSeverityLabel(t *testing.T) {
	cases := map[string]string{
		"critical": "critical",
		"Warning":  "warning",
		"info":     "info",
		"":         "",
		"  ":       "",
	}
	for in, want := range cases {
		if got := severityLabel(in); got != want {
			t.Fatalf("severityLabel(%q) = %q want %q", in, got, want)
		}
	}
}

func TestSignatureMarker(t *testing.T) {
	got := formatMarker("abc")
	want := `<!-- alert-triage:{"sig":"abc"} -->`
	if got != want {
		t.Fatalf("marker = %q want %q", got, want)
	}
}

func formatMarker(s string) string { return fmt.Sprintf(signatureMarker, s) }