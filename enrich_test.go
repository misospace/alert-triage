package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPodList(t *testing.T) {
	data := []byte(`{"items":[{"metadata":{"name":"p1","namespace":"ns1"},"status":{"phase":"Failed"}}]}`)
	var got podList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Metadata.Name != "p1" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestPodListEmpty(t *testing.T) {
	var got podList
	if err := json.Unmarshal([]byte(`{"items":[]}`), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestNodeList(t *testing.T) {
	data := []byte(`{"items":[{"metadata":{"name":"n1"},"status":{"conditions":[{"type":"Ready","status":"False"}]}}]}`)
	var got nodeList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Metadata.Name != "n1" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestEventList(t *testing.T) {
	data := []byte(`{"items":[{"reason":"NodeNotReady","message":"node n1 not ready"}]}`)
	var got eventList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Reason != "NodeNotReady" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestFluxList(t *testing.T) {
	data := []byte(`{"items":[{"metadata":{"name":"f1","namespace":"flux"},"status":{"conditions":[{"type":"Ready","status":"False"}]}}]}`)
	var got fluxList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Metadata.Name != "f1" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestFluxListEmpty(t *testing.T) {
	var got fluxList
	if err := json.Unmarshal([]byte(`{"items":[]}`), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestStripSecrets(t *testing.T) {
	fakeJWT := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.fakesigvalue1234"
	tests := []struct {
		in, want string
	}{
		// Bare keyword[=:] shapes: value consumed, but where the match
		// starts mid-name a key fragment survives (GITHUB_, X-Vault-) —
		// the value is what must not leak.
		{"api_key=abc123", "[REDACTED]"},
		{"password: mysecret", "[REDACTED]"},
		{"token = xyz789", "[REDACTED]"},
		{"env: GITHUB_TOKEN=ghp_faketoken123456", "env: GITHUB_[REDACTED]"},
		{"X-Vault-Token: hvs.faketoken123", "X-Vault-[REDACTED]"},
		{"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "[REDACTED]"},
		{"aws_secret_access_key: wJalrXUtnFEMIfake", "[REDACTED]"},
		// Authorization header: space-separated Bearer token, name kept.
		// Digit-bearing tokens are redacted from eight characters; seven
		// survive the floor.
		{"authorization: Bearer abc1234", "authorization: Bearer abc1234"},
		{"authorization: Bearer abc12345", "authorization: [REDACTED]"},
		{"authorization: Bearer abcdefghij123456", "authorization: [REDACTED]"},
		// Hex runs are credential material even when every character is a
		// letter, and case does not matter.
		{"authorization: Bearer deadbeefdeadbeef", "authorization: [REDACTED]"},
		{"Bearer DEADBEEF", "[REDACTED]"},
		// Percent-encoding is part of the token: nothing left behind.
		{"authorization: Bearer dXNlcjpwYXNzd29yZDEyMzQ%3Dextra", "authorization: [REDACTED]"},
		// Letter-and-hyphen runs reaching beyond the hex alphabet are
		// prose: the guard spares them, which also documents the accepted
		// residual (a pure alphabetic+hyphen credential escapes).
		{"Bearer token-expiry-validation-failed-check-logs", "Bearer token-expiry-validation-failed-check-logs"},
		{"Bearer alpha-only-credential-string", "Bearer alpha-only-credential-string"},
		{"authorization: Bearer " + fakeJWT, "authorization: [REDACTED]"},
		// Quoted-key JSON with quoted value: key preserved, value gone.
		// Prefixed keys (access_token, client_secret, db_password) are
		// covered too and re-emitted intact.
		{`error authenticating: {"password": "hunter2"} rejected`,
			`error authenticating: {"password": "[REDACTED]"} rejected`},
		{`{"access_token": "` + fakeJWT + `"}`, `{"access_token": "[REDACTED]"}`},
		{`{"client_secret": "s3cr3tfake"}`, `{"client_secret": "[REDACTED]"}`},
		{`{"db_password": "hunter2"}`, `{"db_password": "[REDACTED]"}`},
		{`{"token": "tok_fake123456"}`, `{"token": "[REDACTED]"}`},
		{`{"secret":"s3cr3tfake"}`, `{"secret":"[REDACTED]"}`},
		{`{"api_key": "ak_fake123456"}`, `{"api_key": "[REDACTED]"}`},
		{`{"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE"}`,
			`{"aws_access_key_id": "[REDACTED]"}`},
		// Escaped quote inside the value must not leave a remnant.
		{`{"password": "a\"b"}`, `{"password": "[REDACTED]"}`},
		// Both shapes on one line: each pattern owns its half, no remnant.
		{`password=abc {"token": "xyz"}`, `[REDACTED] {"token": "[REDACTED]"}`},
		// Prose that must survive untouched.
		{"no secrets here", "no secrets here"},
		{"bearer authentication failed", "bearer authentication failed"},
		{`{"note": "password policy updated"}`, `{"note": "password policy updated"}`},
	}
	for _, tt := range tests {
		got := stripSecrets(tt.in)
		if got != tt.want {
			t.Errorf("stripSecrets(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

func TestStripSecretsBasicAuth(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.fakesigvalue1234"
	tests := []struct {
		in, want string
	}{
		// Header form: the credential is consumed and the header name
		// stays visible, so the operator can still see what was stripped.
		{"authorization: Basic dXNlcjpwYXNz", "authorization: [REDACTED]"},
		{"Authorization: Basic dXNlcjpwYXNzd29yZA==", "Authorization: [REDACTED]"},
		{"Proxy-Authorization: Basic dXNlcjpwYXNz", "Proxy-Authorization: [REDACTED]"},
		{`{"authorization": "Basic dXNlcjpwYXNz"}`, `{"authorization": "[REDACTED]"}`},
		{"authorization=Basic dXNlcjpwYXNz", "authorization=[REDACTED]"},
		{"GET /x HTTP/1.1 Authorization: Basic dXNlcjpwYXNz", "GET /x HTTP/1.1 Authorization: [REDACTED]"},
		// A short credential decodes to a user:password pair, so it goes
		// even though it is too short to look like credential material.
		{"authorization: Basic dTpw", "authorization: [REDACTED]"},
		// The slot after the scheme holds the credential, so a mangled one
		// is redacted too: half a credential still authenticates.
		{"authorization: Basic YWRtaW4", "authorization: [REDACTED]"},
		// A header value that carries the credential without naming the
		// scheme still decodes to one, so it goes too. Punctuation after
		// the credential is not part of it.
		{"authorization: dXNlcjpwYXNz", "authorization: [REDACTED]"},
		{"authorization=dXNlcjpwYXNz,host=example", "authorization=[REDACTED],host=example"},
		// Bare scheme: the scheme word stays visible, and words between
		// the scheme and the credential are tolerated.
		{"basic dXNlcjpwYXNz", "basic [REDACTED]"},
		{"basic YWRtaW46YWRtaW4=", "basic [REDACTED]"},
		{"basic auth: dXNlcjpwYXNz", "basic auth: [REDACTED]"},
		{"basic auth dXNlcjpwYXNz", "basic auth [REDACTED]"},
		{"basic: dXNlcjpwYXNz", "basic: [REDACTED]"},
		{"basic dXNlcjpwYXNz,host=example", "basic [REDACTED],host=example"},
		// Percent-encoded separator between the scheme word and the
		// credential: URL- and query-encoded auth values logged by proxies
		// and web apps. In a header the whole value is consumed; outside
		// one the scheme word stays visible as context.
		{"proxy-authorization: Basic%20Zm9vOmJhcg%3D%3D", "proxy-authorization: [REDACTED]"},
		{"authorization=Basic%20dXNlcjpwYXNz", "authorization=[REDACTED]"},
		{"basic%20Zm9vOmJhcg%3D%3D", "basic%20[REDACTED]"},
		{"basic%3AdXNlcjpwYXNz", "basic%3A[REDACTED]"},
		// Prose survives the encoded separators too: the decode gate still
		// decides scheme-word-only matches, and a sentence containing the
		// scheme word stays byte-identical.
		{"basic%20authentication failed", "basic%20authentication failed"},
		{"basic auth failed for basic.io keep this sentence", "basic auth failed for basic.io keep this sentence"},
		// Prose survives. Words that also decode to bytes holding a colon
		// ("open" decodes to bytes that start with one, "2006" to bytes
		// whose user-id is not printable) are not credentials.
		{"basic authentication failed", "basic authentication failed"},
		{"basic verification failed", "basic verification failed"},
		{"basic auth required", "basic auth required"},
		{"basic incompatibility detected", "basic incompatibility detected"},
		{"basic Output", "basic Output"},
		{"basic Open", "basic Open"},
		{"basic 2006", "basic 2006"},
		// The scheme word must start a word, and a header value that is
		// no credential is left alone.
		{"subbasic dXNlcjpwYXNz", "subbasic dXNlcjpwYXNz"},
		{"authorization: Basic", "authorization: Basic"},
		{"authorization: Digest abc123", "authorization: Digest abc123"},
		{"no secrets here", "no secrets here"},
		// Dotted-JWT and percent-encoded fragments: the tail glued to the
		// credential core is consumed with it, leaving no remnant next to
		// "[REDACTED]".
		{"authorization: Basic " + jwt, "authorization: [REDACTED]"},
		{"Basic " + jwt, "Basic [REDACTED]"},
		{"basic " + jwt, "basic [REDACTED]"},
		{"basic bearer " + jwt, "basic bearer [REDACTED]"},
		{"Basic dXNlcjpwYXNz%3Dextra", "Basic [REDACTED]"},
		{"authorization: Basic dXNlcjpwYXNz%3Dextra", "authorization: [REDACTED]"},
		{"authorization: dXNlcjpwYXNz%3Dextra", "authorization: [REDACTED]"},
		// A sentence-final "." after the credential is not part of it, so it
		// survives the redaction.
		{"basic dXNlcjpwYXNz.", "basic [REDACTED]."},
		{"authorization: Basic dXNlcjpwYXNz. Retrying", "authorization: [REDACTED]. Retrying"},
		// JSON form carrying a dotted JWT: the whole credential goes.
		{`{"authorization": "Basic ` + jwt + `"}`, `{"authorization": "[REDACTED]"}`},
		// A tail that ends on a scheme word is emitted, not consumed, so the
		// next credential keeps its context and is redacted on the next pass.
		{"basic dXNlcjpwYXNz.basic dXVpZDpwYXNz", "basic [REDACTED].basic [REDACTED]"},
		{"authorization: Basic dXNlcjpwYXNz.basic dXVpZDpwYXNz", "authorization: [REDACTED].basic [REDACTED]"},
		{"basic dXNlcjpwYXNz.authorization: Basic dXVpZDpwYXNz", "basic [REDACTED].authorization: [REDACTED]"},
		{"basic dXNlcjpwYXNz.basic", "basic [REDACTED].basic"},
		// A tail that carries credential material ahead of the trailing
		// scheme word leaks it: the tail's character class swallows the
		// credential and no later pass can consume it, so the interior is
		// redacted (#217). The scheme word stays, so the next credential
		// keeps its context.
		{"authorization: Zm9vOmJhcg==.dXNlcjpwYXNz.basic", "authorization: [REDACTED].[REDACTED].basic"},
		{"basic Zm9vOmJhcg==.dXNlcjpwYXNz.basic", "basic [REDACTED].[REDACTED].basic"},
		// A JWT glued to the credential and stopped on a scheme word goes
		// the same way: no segment of it survives.
		{"authorization: Basic " + jwt + ".basic", "authorization: [REDACTED].[REDACTED].basic"},
		// The same shape with a credential behind the trailing scheme word:
		// the interior goes and the next credential is still redacted.
		{"basic Zm9vOmJhcg==.dXNlcjpwYXNz.basic dXVpZDpwYXNz", "basic [REDACTED].[REDACTED].basic [REDACTED]"},
		{"authorization: Basic Zm9vOmJhcg==.dXNlcjpwYXNz.basic dXVpZDpwYXNz", "authorization: [REDACTED].[REDACTED].basic [REDACTED]"},
		// The JSON-quoted shape, which is how the header reaches a log in
		// practice.
		{`{"authorization": "Basic Zm9vOmJhcg==.dXNlcjpwYXNz.basic"}`, `{"authorization": "[REDACTED].[REDACTED].basic"}`},
		// A long chain of scheme-word tails is one captured tail: it
		// collapses in a single pass and its interior never leaks.
		{"basic dXNlcjpwYXNz" + strings.Repeat(".basic", 500), "basic [REDACTED].[REDACTED].basic"},
		// The danger tail must not redact on its own: a header value that
		// is no credential survives, and the glued credential behind the
		// scheme word is still redacted by the scheme pass.
		{"authorization: Negotiate.basic dXVpZDpwYXNz", "authorization: Negotiate.basic [REDACTED]"},
		// Percent-encoded glue hides the next credential's scheme word from
		// the tail rule: the tail was consumed, so the scheme word went
		// with it and the credential behind it kept its plaintext. The
		// tail rule has to count the encoded glue, and the scheme word has
		// to be recognised where a percent-encoded token ends in a hex
		// digit, because no word boundary fires there.
		{"basic dXNlcjpwYXNz%3Dbasic dXVpZDpwYXNz", "basic [REDACTED]%3Dbasic [REDACTED]"},
		{"basic dXNlcjpwYXNz%3abasic dXVpZDpwYXNz", "basic [REDACTED]%3abasic [REDACTED]"},
		// The tail rule must honour every percent token the scheme-word
		// boundary honours, not just the encoded separators: the scheme
		// pass reads a scheme word after ANY percent token, so a tail
		// ending behind an unenumerated one ("%3f" is the encoding of
		// "?") is context the next pass will use, and consuming it
		// orphaned the credential behind that word.
		{"basic dXNlcjpwYXNz%3fbasic dXVpZDpwYXNz", "basic [REDACTED]%3fbasic [REDACTED]"},
		{"basic Zm9vOmJhcg==.dXNlcjpwYXNz%3fbasic dXVpZDpwYXNz", "basic [REDACTED].[REDACTED]%3fbasic [REDACTED]"},
		// The header word in the tail names the scheme of the value that
		// follows it, but the header pass could not read it back without a
		// separator, so the credential behind it kept its plaintext.
		{"basic dXNlcjpwYXNz%3D.authorization dXVpZDpwYXNz", "basic [REDACTED]%3D.authorization [REDACTED]"},
		// A scheme word glued to a percent-encoded token or to a digit is
		// still a scheme word.
		{"%3Dbasic%20dXNlcjpwYXNz", "%3Dbasic%20[REDACTED]"},
		{"0basic%20dXNlcjpwYXNz", "0basic%20[REDACTED]"},
		// A header that lost its separator still names the header, so the
		// value behind it goes when it decodes to a credential.
		{"authorization dXVpZDpwYXNz", "authorization [REDACTED]"},
		// Prose around the header word survives: without a separator the
		// header word says nothing about what follows it, so the value has
		// to decode to a credential before the line is touched.
		{"Authorization Basic scheme is deprecated", "Authorization Basic scheme is deprecated"},
		{"authorization failed", "authorization failed"},
		// A header word that is not a header must not swallow the header
		// behind it: the value of the first one is no credential, so the
		// pass has to keep reading to find the second header.
		{"Authorization-foo.Authorization:dXNlcjpwYXNz", "Authorization-foo.Authorization:[REDACTED]"},
		// A scheme word behind a swallowed one, and a scheme word that is
		// not one because letters are glued to it.
		{"0basic Basic%3DdXNlcjpwYXNz", "0basic Basic%3D[REDACTED]"},
		{"basic dXNlcjpwYXNz.subbasic dXVpZDpwYXNz", "basic [REDACTED] dXVpZDpwYXNz"},
		// The greedy word group used to swallow a credential that words
		// follow and judge the word behind it, leaving the credential in
		// plaintext (issue #224); each interlude run now faces the gate.
		{"failed with basic dXNlcjpwYXNz in request", "failed with basic [REDACTED] in request"},
		{"basic dXNlcjpwYXNz and dXVpZDpwYXNz", "basic [REDACTED] and [REDACTED]"},
		{"basic dXNlcjpwYXNz=basic dXVpZDpwYXNz", "basic [REDACTED]=basic [REDACTED]"},
		// A credential glued to a following scheme word is one token to
		// the core class: it stops at "." but neither at "=" nor at a
		// letter, so the decode gate failed on the combined run and the
		// credential survived next to the word (issue #227). The
		// credential goes and the word stays, so a credential behind it
		// keeps the context the next pass reads.
		{"basic dXVpZDpwYXNz=basic", "basic [REDACTED]=basic"},
		{"basic dXVpZDpwYXNzbasic dXVpZDpwYXNz", "basic [REDACTED]basic [REDACTED]"},
		{"basic dXVpZDpwYXNzbasic", "basic [REDACTED]basic"},
		// A digit-bearing credential cannot enter the word chain, so the
		// core swallows its "=" glue together with the glued word. The
		// "="-join keeps its separator, so the output shows the join
		// just as the letter form's chain does.
		{"basic dXNlcjE6cA=basic", "basic [REDACTED]=basic"},
		{"basic dXNlcjE6cA=basic dXVpZDpwYXNz", "basic [REDACTED]=basic [REDACTED]"},
		// The header twin: the value class glued word and credential into
		// one run, the gate failed, and the value survived unread.
		{"authorization: dXVpZDpwYXNzbasic", "authorization: [REDACTED]basic"},
		{"authorization: dXVpZDpwYXNzauthorization dXVpZDpwYXNz", "authorization: [REDACTED]authorization [REDACTED]"},
		// Prose that ends on the scheme word without a credential ahead
		// of it survives the cut.
		{"basic authorization", "basic authorization"},
		{"authorization: Negotiate basic", "authorization: Negotiate basic"},
		// A "+" glued to a scheme word: the following word's first letters
		// were base64 alphabet chars, so the split's glue set "=_-" came
		// up short and the part before the word failed the gate (issue
		// #240). The glue set grew by "+/" and the split fires again. The
		// credential goes; the word and the following credential keep
		// their context. The "="-join residue before the word stays
		// readable, exactly as the digit joins' separators do (#230,
		// #238).
		{"Basic: Zm9vOmJhcg==+authorization dXNlcjE6cA=", "Basic: [REDACTED]==+authorization [REDACTED]"},
		// A scheme word inside the run's middle is not at either end, so
		// splitGluedSchemeWord's suffix walk never saw it: every credential
		// around the word survived. The segments the word splits face the
		// gate on their own, the words stay as context.
		{"authorization: dXVpZDpwYXNzauthorization=dXVpZDpwYXNz", "authorization: [REDACTED]authorization=[REDACTED]"},
		{"basic dXVpZDpwYXNzbasic-dXNlcjpwYXNz", "basic [REDACTED]basic-[REDACTED]"},
		{"basic Zm9vOmJhcg+basic-dXNlcjpwYXNz", "basic [REDACTED]basic-[REDACTED]"},
		// A word-shaped fragment ahead of the glued word is prose: no
		// segment before the word decodes, so only the payload behind the
		// two goes and the prose keeps its text.
		{"basic sub-basic-dXNlcjpwYXNz", "basic sub-basic-[REDACTED]"},
		// Prose whose fragments carry scheme words stays readable: no
		// segment around any occurrence decodes.
		{"basic subbasic", "basic subbasic"},
		{"basic offbasic", "basic offbasic"},
		// A credential joined by "=" to a token whose other side carries a
		// mid-run scheme word: the join's left slot is redacted by the
		// key-slot rule (#238) and the word-split judgement covers the
		// credential behind the word (#240).
		{"basic Zm9vOmJhcg=basic-dXNlcjpwYXNz", "basic [REDACTED]=basic-[REDACTED]"},
		{"basic Zm9vOmJhcg=authorization-dXNlcjpwYXNz", "basic [REDACTED]=authorization-[REDACTED]"},
		// A "+"/"/"-glued run the "=" join cannot cut on still sees its
		// word split, with the glue left of the word going with the
		// credential.
		{"basic Zm9vOmJhcg+basic-dXNlcjpwYXNz.more", "basic [REDACTED]basic-[REDACTED]"},
		// The "/" glue, whose shape is the same "+"-family one: the base64
		// alphabet char nothing later can read goes with the redacted
		// credential, the word and everything behind it stay.
		{"basic Zm9vOmJhcg/basic-dXNlcjpwYXNz", "basic [REDACTED]basic-[REDACTED]"},
		{"basic dXVpZDpwYXNz/basic", "basic [REDACTED] basic"},
		// A trailing-glued word behind an "=" join (issue #240, review):
		// redactJoinSegments judged the segment "dXVpZDpwYXNzbasic" whole
		// and re-emitted it verbatim, its payload surviving next to the
		// word; the word-segment judgement below covers the segment.
		{"basic key1=dXVpZDpwYXNzbasic", "basic key1=[REDACTED]basic"},
		// The same residual nested in an "="-joined header value: the
		// segment "key=dXVpZDpwYXNz_basicdXVpZDpwYXNz" fails the gate
		// whole, so the join inside the segment judges both slots and the
		// credential behind the trailing word goes (#240, review).
		{"authorization: key=dXVpZDpwYXNz_basicdXVpZDpwYXNz", "authorization: key=[REDACTED]_basic[REDACTED]"},
		// The leading separators are judged apart from the word chain, so a
		// percent-encoded one cannot glue its digits onto the leftmost run,
		// and the scheme word keeps its case in the output.
		{"basic%20dXNlcjpwYXNz in request", "basic%20[REDACTED] in request"},
		{"BASIC dXNlcjpwYXNz in request", "BASIC [REDACTED] in request"},
		// Accepted trade: the word chain cannot tell a credential's "="
		// padding from the "=" separator it matched, so the padding residue
		// survives after "[REDACTED]" rather than a swallowed join. The
		// payload itself never does, and the residue decodes to nothing.
		{"basic dXNlcjpwYXNz== and more", "basic [REDACTED]== and more"},
		// A credential that carries digits cannot enter the word chain, and
		// glued to a following token by "=" it cannot decode as a whole
		// either, because an interior "=" is not valid base64 — so the core
		// was rejected and the credential kept its plaintext (issue #230).
		// The part before the join faces the gate on its own, and the join
		// stays readable.
		{"basic Zm9vOmJhcg=request", "basic [REDACTED]=request"},
		{"basic Zm9vOmJhcg=trailing", "basic [REDACTED]=trailing"},
		{"basic%20Zm9vOmJhcg=request", "basic%20[REDACTED]=request"},
		{"basic auth Zm9vOmJhcg=request", "basic auth [REDACTED]=request"},
		// The credential's own "=" padding and the join are two separators:
		// both stay, because neither is credential material.
		{"basic YWRtaW46YWRtaW4==trailing", "basic [REDACTED]==trailing"},
		// A header names the scheme of its value, so the whole value goes.
		{"authorization: Basic Zm9vOmJhcg=request", "authorization: [REDACTED]"},
		// A "key=value" shape whose key is no credential is prose, and the
		// join alone must not turn it into one. The key carries a digit
		// here, so the word chain cannot swallow it and the join really
		// reaches the gate.
		{"basic auth=failed", "basic auth=failed"},
		{"basic key=value", "basic key=value"},
		{"basic key1=value", "basic key1=value"},
		// A tail on a glued credential follows the rule of a tail on a
		// redacted core: a tail that stops on a scheme word is emitted, so
		// the credential behind it keeps its context and is redacted, and a
		// tail that stops on no scheme word goes with the credential.
		{"basic Zm9vOmJhcg=request.basic dXVpZDpwYXNz", "basic [REDACTED]=request.basic [REDACTED]"},
		{"basic Zm9vOmJhcg=request.dXNlcjpwYXNz", "basic [REDACTED]=request"},
		// #238: credentials in both positions of key=value joins are redacted.
		{"basic abc1=Zm9vOmJhcg", "basic abc1=[REDACTED]"},
		{"basic key1=Zm9vOmJhcg", "basic key1=[REDACTED]"},
		{"basic x9=Ym9vdGFpbjpzZWNyZXQ", "basic x9=[REDACTED]"},
		{"basic Zm9vOmJhcg=Zm9vOmJhcg", "basic [REDACTED]=[REDACTED]"},
		// Prose-only join segments survive.
		{"basic id2=user123", "basic id2=user123"},
		{"basic a1=b2", "basic a1=b2"},
		{"basic abc1=deadbeef", "basic abc1=deadbeef"},
	}
	for _, tt := range tests {
		got := stripSecrets(tt.in)
		if got != tt.want {
			t.Errorf("stripSecrets(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

// TestStripSecretsBasicAuthPayloadGone pins the property that matters for
// the fix: the credential itself never reaches the digest, whichever form
// it arrived in.
func TestStripSecretsBasicAuthPayloadGone(t *testing.T) {
	const payload = "dXNlcjpwYXNz"
	for _, in := range []string{
		"authorization: Basic " + payload,
		`{"authorization": "Basic ` + payload + `"}`,
		"basic " + payload,
		"authorization: " + payload,
		// An "=" join inside a declined header value folds the
		// credential into one undecodable value (#246).
		"authorization: Negotiate=" + payload,
		// The scheme word glued to a percent-encoded token or to a digit:
		// no word boundary fires there, so the credential behind it used
		// to survive.
		"%3Dbasic%20" + payload,
		"0basic%20" + payload,
		// A header that lost its separator, and a header word that is not
		// a header standing in front of a real one.
		"authorization dXNpZDpwYXNz",
		"Authorization-foo.Authorization:" + payload,
		// A scheme word glued to a digit or a percent-encoded token, with
		// a second scheme word behind it: the first match swallows the
		// second scheme word, and the credential behind it must still go.
		"0basic Basic%3D" + payload,
		"authorization " + payload + ".re-basic dXNpZDpwYXNz",
	} {
		if got := stripSecrets(in); strings.Contains(got, payload) {
			t.Errorf("stripSecrets(%q) = %q; basic-auth payload survived", in, got)
		}
	}

	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.fakesigvalue1234"
	// A dotted JWT: every segment must be gone, not just the first; and for a
	// percent-encoded fragment the "%3Dextra" tail must go as well.
	for _, in := range []string{
		"authorization: Basic " + jwt,
		"Basic " + jwt,
		"basic " + jwt,
	} {
		for _, seg := range []string{"eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJmYWtlIn0", "fakesigvalue1234"} {
			if got := stripSecrets(in); strings.Contains(got, seg) {
				t.Errorf("stripSecrets(%q) = %q; JWT segment %q survived", in, got, seg)
			}
		}
	}
	for _, in := range []string{
		"Basic dXNlcjpwYXNz%3Dextra",
		"authorization: Basic dXNlcjpwYXNz%3Dextra",
		"authorization: dXNlcjpwYXNz%3Dextra",
	} {
		if got := stripSecrets(in); strings.Contains(got, "%3Dextra") {
			t.Errorf("stripSecrets(%q) = %q; percent-encoded tail survived", in, got)
		}
	}
	// Two adjacent credentials separated by ".": the second one leaked when
	// the tail swallowed its scheme word, so check both payloads per input.
	// The same chain with the glue percent-encoded leaked the same way: the
	// tail rule did not see the encoded separator, so the scheme word of
	// the second credential was swallowed with the tail.
	for _, in := range []string{
		"basic dXNlcjpwYXNz.basic dXVpZDpwYXNz",
		"basic dXNlcjpwYXNz%3Dbasic dXVpZDpwYXNz",
		"basic dXNlcjpwYXNz%3abasic dXVpZDpwYXNz",
		"basic dXNlcjpwYXNz%3D.authorization dXVpZDpwYXNz",
		// Two credentials joined by "=" in one declined header value:
		// every segment faces the gate, not just the one that first
		// consumes the match (#246).
		"authorization: dXNlcjpwYXNz=key=dXVpZDpwYXNz",
		// A scheme word glued inside a join segment must survive as the
		// trailing credential's context, not be swallowed with the
		// segment (#246).
		"authorization: key=dXVpZDpwYXNz_basic dXVpZDpwYXNz",
	} {
		for _, p := range []string{payload, "dXVpZDpwYXNz"} {
			if got := stripSecrets(in); strings.Contains(got, p) {
				t.Errorf("stripSecrets(%q) = %q; payload %q survived", in, got, p)
			}
		}
	}
	// The greedy word group used to swallow a credential that words follow and
	// judge the word behind it (issue #224); both payloads must be gone.
	for _, in := range []string{
		"failed with basic dXNlcjpwYXNz in request",
		"basic dXNlcjpwYXNz and dXVpZDpwYXNz",
		"basic dXNlcjpwYXNz=basic dXVpZDpwYXNz",
		"basic%20dXNlcjpwYXNz in request",
		"BASIC dXNlcjpwYXNz in request",
		"basic dXNlcjpwYXNz== and more",
	} {
		for _, p := range []string{payload, "dXVpZDpwYXNz"} {
			if got := stripSecrets(in); strings.Contains(got, p) {
				t.Errorf("stripSecrets(%q) = %q; payload %q survived", in, got, p)
			}
		}
	}
	// A credential glued to a following scheme word was one token to the
	// core class, and the gate failing on the combined run spared the
	// whole thing (issue #227); no payload may survive, glued form
	// included.
	for _, in := range []string{
		"basic dXVpZDpwYXNzbasic dXVpZDpwYXNz",
		"basic dXNlcjE6cA=basic dXVpZDpwYXNz",
		"authorization: dXVpZDpwYXNzbasic authorization dXVpZDpwYXNz",
	} {
		for _, p := range []string{payload, "dXVpZDpwYXNz", "dXNlcjE6cA"} {
			if got := stripSecrets(in); strings.Contains(got, p) {
				t.Errorf("stripSecrets(%q) = %q; payload %q survived", in, got, p)
			}
		}
	}
	// A "+" or "/" gluing one credential to a following scheme word, and a
	// scheme word inside a run with credentials on either side, kept their
	// plaintext on main (issue #240): no payload of any of the shapes may
	// survive, glued or mid-run.
	for _, in := range []string{
		"Basic: Zm9vOmJhcg==+authorization dXNlcjE6cA=",
		"authorization: dXVpZDpwYXNzauthorization=dXVpZDpwYXNz",
		"basic dXVpZDpwYXNzbasic-dXNlcjpwYXNz",
		"basic Zm9vOmJhcg+basic-dXNlcjpwYXNz",
	} {
		for _, p := range []string{payload, "Zm9vOmJhcg", "dXVpZDpwYXNz", "dXNlcjpwYXNz", "dXNlcjE6cA"} {
			if got := stripSecrets(in); strings.Contains(got, p) {
				t.Errorf("stripSecrets(%q) = %q; payload %q survived", in, got, p)
			}
		}
	}
	// A gate-failing "=" segment was re-emitted verbatim, so a scheme word
	// glued to its end or a glue run leading it kept the segment's payload
	// (issue #259); the segment is judged on its own now, so every payload
	// goes while the word and the glue survive as context.
	for _, in := range []string{
		"authorization: dXNlcjpwYXNz=dXVpZDpwYXNzbasic",
		"authorization: dXNlcjpwYXNz=-dXVpZDpwYXNz",
		"authorization: key=dXVpZDpwYXNzbasic",
		"authorization: key=-dXVpZDpwYXNz",
		"basic dXNlcjE6cA=dXVpZDpwYXNzbasic",
		"basic dXNlcjE6cA=-dXVpZDpwYXNz",
	} {
		for _, p := range []string{payload, "dXVpZDpwYXNz", "dXNlcjE6cA"} {
			if got := stripSecrets(in); strings.Contains(got, p) {
				t.Errorf("stripSecrets(%q) = %q; payload %q survived", in, got, p)
			}
		}
	}
	// A credential that carries digits cannot enter the word chain, so a
	// digit-bearing payload glued to a following token by "=" reached the
	// digest in plaintext (issue #230). The payload must go whatever the
	// join is.
	const digitPayload = "Zm9vOmJhcg"
	for _, in := range []string{
		"basic " + digitPayload + "=request",
		"basic " + digitPayload + "=trailing",
		"basic%20" + digitPayload + "=request",
		"basic auth " + digitPayload + "=request",
		"authorization: Basic " + digitPayload + "=request",
	} {
		if got := stripSecrets(in); strings.Contains(got, digitPayload) {
			t.Errorf("stripSecrets(%q) = %q; basic-auth payload survived", in, got)
		}
	}
}

// TestStripSecretsBasicAuthGluedByEqualsGone pins that the credential in
// the scheme word's slot is redacted whatever token follows the join, and
// that the token itself survives: the join is what makes the core
// undecodable, so the credential has to be judged on its own (issue #230).
func TestStripSecretsBasicAuthGluedByEqualsGone(t *testing.T) {
	const cred = "Zm9vOmJhcg"
	for _, join := range []string{"request", "trailing", "more", "a=b", "x", "1234"} {
		in := "basic " + cred + "=" + join
		got := stripSecrets(in)
		if strings.Contains(got, cred) {
			t.Errorf("stripSecrets(%q) = %q; credential survived", in, got)
		}
		if !strings.Contains(got, join) {
			t.Errorf("stripSecrets(%q) = %q; the joined token %q did not survive", in, got, join)
		}
	}
}

// TestStripSecretsBasicAuthJoinSegmentCutsGone pins the segment-level
// residues of a declined "="-joined value (issue #259): a segment that
// fails the decode gate on its own is not re-emitted verbatim. A scheme
// word glued to a gate-failing segment is cut the way the #227 cuts cut
// it, and a leading glue run the gate fails on is trimmed before the gate
// is faced again, the glue staying where the line carried it. The payload
// goes in the header arm and the scheme core alike, the key slot and the
// word stay readable as context, prose survives, and the output is stable
// under a second pass.
func TestStripSecretsBasicAuthJoinSegmentCutsGone(t *testing.T) {
	tests := []struct{ in, want string }{
		// A trailing scheme word glued to a gate-failing segment kept the
		// segment's payload (issue #259, shape 1).
		{"authorization: dXNlcjpwYXNz=dXVpZDpwYXNzbasic", "authorization: [REDACTED]=[REDACTED]basic"},
		{"basic dXNlcjE6cA=dXVpZDpwYXNzbasic", "basic [REDACTED]=[REDACTED]basic"},
		// A leading glue run the gate fails on kept the segment's payload
		// (issue #259, shape 2): the glue is trimmed for the gate and stays
		// in place.
		{"authorization: dXNlcjpwYXNz=-dXVpZDpwYXNz", "authorization: [REDACTED]=-[REDACTED]"},
		{"basic dXNlcjE6cA=-dXVpZDpwYXNz", "basic [REDACTED]=-[REDACTED]"},
		// The same cuts with a non-credential key in the first slot: the
		// key and the glue it carries stay readable, the payload does not.
		{"authorization: key=dXVpZDpwYXNzbasic", "authorization: key=[REDACTED]basic"},
		{"authorization: key=-dXVpZDpwYXNz", "authorization: key=-[REDACTED]"},
		// Two joins: every credential-bearing segment is judged on its own.
		{"authorization: a=dXNlcjpwYXNz=dXVpZDpwYXNz", "authorization: a=[REDACTED]=[REDACTED]"},
		// A "+"-glued word inside a segment that decodes whole: the word is
		// cut out with a real space (the #242 cut), so the credential behind
		// it keeps its scheme-word context and is redacted on the next pass.
		{"authorization: key=dXVpZDpwYXNz+basic dXNlcjpwYXNz", "authorization: key=[REDACTED] basic [REDACTED]"},
		// The same cut with glue leading the segment: the glue stays where
		// the line carried it, the word is still cut out, and the follower
		// is redacted on the next pass.
		{"authorization: key=-dXNlcjpwYXNz=-dXVpZDpwYXNz+basic dXNlcjE6cA", "authorization: key=-[REDACTED]=-[REDACTED] basic [REDACTED]"},
		// Prose: a segment that decodes to nothing is untouched, and a
		// value with no decodable segment is returned unchanged.
		{"authorization: key=value", "authorization: key=value"},
		{"authorization: key=-value", "authorization: key=-value"},
	}
	for _, tt := range tests {
		if got := stripSecrets(tt.in); got != tt.want {
			t.Errorf("stripSecrets(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
	// The cuts re-emit glue and a scheme word as context, so a second pass
	// must leave the output unchanged: the digest is rendered from text
	// that has been through the function once.
	for _, tt := range tests {
		once := stripSecrets(tt.in)
		if twice := stripSecrets(once); twice != once {
			t.Errorf("stripSecrets(%q) = %q; second pass = %q", tt.in, once, twice)
		}
	}
	// Whatever the joins carry, no credential payload may reach the digest.
	for _, in := range []string{
		"authorization: dXNlcjpwYXNz=dXVpZDpwYXNzbasic",
		"authorization: dXNlcjpwYXNz=-dXVpZDpwYXNz",
		"basic dXNlcjE6cA=dXVpZDpwYXNzbasic",
		"basic dXNlcjE6cA=-dXVpZDpwYXNz",
		"authorization: key=dXVpZDpwYXNzbasic",
		"authorization: key=-dXVpZDpwYXNz",
		"authorization: key=dXNlcjpwYXNz=-dXVpZDpwYXNz",
		"authorization: key=_dXVpZDpwYXNz",
		`{"authorization": "dXNlcjpwYXNz=dXVpZDpwYXNzbasic"}`,
	} {
		got := stripSecrets(in)
		for _, p := range []string{"dXVpZDpwYXNz", "dXNlcjpwYXNz", "dXNlcjE6cA"} {
			if strings.Contains(got, p) {
				t.Errorf("stripSecrets(%q) = %q; payload %q survived", in, got, p)
			}
		}
	}
}

// TestStripSecretsBasicAuthVetoedTailJudged pins that a match the decode
// test declines still loses the credentials its captured tail carries
// (#226). The tail's character class swallows whole credential segments,
// and no pass can rescan what it left in play — a credential sitting
// before the scheme word a pass looks for first is never matched — so the
// tail is judged on its way out. Glue and runs that decode to nothing
// (prose, the scheme word) survive, so redaction stays confined to the
// material; a tail that carries nothing to redact keeps its match
// byte-identical.
func TestStripSecretsBasicAuthVetoedTailJudged(t *testing.T) {
	tests := []struct{ in, want string }{
		{"authorization: Negotiate.dXNlcjpwYXNz.basic", "authorization: Negotiate.[REDACTED].basic"},
		{"authorization: Negotiate.dXNlcjpwYXNz", "authorization: Negotiate.[REDACTED]"},
		{"basic Basic.dXNlcjpwYXNz", "basic Basic.[REDACTED]"},
		{"basic Basic.dXNlcjpwYXNz.basic", "basic Basic.[REDACTED].basic"},
		// The glue a later pass may need survives the judgement, so a
		// percent-encoded separator between the declined core and its
		// credential keeps the match's own shape.
		{"0basic Basic%3DdXNlcjpwYXNz", "0basic Basic%3D[REDACTED]"},
		// A tail that carries no decoding piece is untouched: the declined
		// value and the tail both stay readable.
		{"authorization: Negotiate.slow-connection.timeout", "authorization: Negotiate.slow-connection.timeout"},
		// A credential behind a percent-encoded glue inside the tail is one
		// of the pieces: the glue's hex digits must not break a piece's
		// decode (the scheme pass captures the encoded separators apart
		// from its word chain for the same reason).
		{"authorization: Negotiate.dXNlcjpwYXNz%3adXVpZDpwYXNz", "authorization: Negotiate.[REDACTED]%3a[REDACTED]"},
		// Several credentials in one tail all go, and the padding of a
		// credential that stops on "=" survives as residue.
		{"authorization: Negotiate.dXNlcjpwYXNz.dXVpZDpwYXNz", "authorization: Negotiate.[REDACTED].[REDACTED]"},
		{"authorization: Negotiate.dXNlcjpwYXNzd29yZA==.basic", "authorization: Negotiate.[REDACTED]==.basic"},
		// A key=value join in the tail carries a credential behind the
		// separator, not after the piece; the join survives, the credential
		// does not.
		{"authorization: Negotiate.key=dXNlcjpwYXNz", "authorization: Negotiate.key=[REDACTED]"},
		// The next credential behind a judged tail keeps its context and is
		// still redacted.
		{"authorization: Negotiate.dXNlcjpwYXNz.basic dXVpZDpwYXNz", "authorization: Negotiate.[REDACTED].basic [REDACTED]"},
		{"authorization: Negotiate.dXNlcjpwYXNz.authorization: dXNpZDpwYXNz", "authorization: Negotiate.[REDACTED].authorization: [REDACTED]"},
		// The JSON-quoted shape, which is how the header reaches a log in
		// practice.
		{`{"authorization": "Negotiate.dXNlcjpwYXNz.basic"}`, `{"authorization": "Negotiate.[REDACTED].basic"}`},
	}
	for _, tt := range tests {
		got := stripSecrets(tt.in)
		if got != tt.want {
			t.Errorf("stripSecrets(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

// TestStripSecretsBasicAuthVetoedValueJoinJudged pins that a declined header
// match still loses the credential its value carries behind an "=" join
// (#246). The value's character class folds an equality-joined credential
// into one undecodable value, and the tail group needs a "." or "%" opener,
// so the folded credential is never a piece either gate reaches: each
// segment of the value has to face the decode gate on its own, as the
// scheme core's segments already do (#238). A value with no credential
// stays byte-identical — prose, and key=value joins that hold none.
func TestStripSecretsBasicAuthVetoedValueJoinJudged(t *testing.T) {
	tests := []struct{ in, want string }{
		// The reproduction from the issue: a non-Basic scheme name
		// joins the header value to a credential.
		{"authorization: Negotiate=dXNlcjpwYXNz", "authorization: Negotiate=[REDACTED]"},
		{"authorization: Negotiate=dXVpZDpwYXNz", "authorization: Negotiate=[REDACTED]"},
		// Multi-"=" joins: one decoding segment is not enough to consume
		// the match, every segment is judged.
		{"authorization: dXNlcjpwYXNz=key=dXVpZDpwYXNz", "authorization: [REDACTED]=key=[REDACTED]"},
		{"authorization: key=dXNlcjpwYXNz", "authorization: key=[REDACTED]"},
		// The whitespace-separated header form declines the scheme word's
		// warranty too, and judges the value's segments the same way.
		{"authorization Basic key=dXNlcjpwYXNz", "authorization Basic key=[REDACTED]"},
		// The credential's own "=" padding and the join are two
		// separators; both survive as residue, the payload does not.
		{"authorization: Negotiate=dXNlcjpwYXNzd29yZA==", "authorization: Negotiate=[REDACTED]=="},
		// Text behind the value is outside the match and survives.
		{"authorization: Negotiate=dXNlcjpwYXNz in request", "authorization: Negotiate=[REDACTED] in request"},
		// A tail on a join-declined value is judged with the value in the
		// same match.
		{"authorization: Negotiate=dXNlcjpwYXNz.dXVpZDpwYXNz", "authorization: Negotiate=[REDACTED].[REDACTED]"},
		// Only the value is consumed by the judgement, so a later header
		// hiding in the tail is still read.
		{"authorization: Negotiate=dXNlcjpwYXNz.authorization: dXVpZDpwYXNz", "authorization: Negotiate=[REDACTED].authorization: [REDACTED]"},
		// The next credential behind a judged value keeps its context and
		// is redacted by the scheme pass.
		{"authorization: Negotiate=dXNlcjpwYXNz basic dXVpZDpwYXNz", "authorization: Negotiate=[REDACTED] basic [REDACTED]"},
		// The JSON-quoted shape, which is how the header reaches a log in
		// practice.
		{`{"authorization": "Negotiate=dXNlcjpwYXNz"}`, `{"authorization": "Negotiate=[REDACTED]"}`},
		// A gate-passing segment may carry a scheme word glued inside it
		// ("_basic" is base64-url alphabet): the word is the next
		// credential's context and is re-emitted, as it is behind an
		// accepted run — swallowing it would orphan the trailing
		// credential (#246). The join arm is shared with the scheme
		// core, which gets the same judgement.
		{"authorization: key=dXVpZDpwYXNz_basic dXVpZDpwYXNz", "authorization: key=[REDACTED] basic [REDACTED]"},
		{"basic key12=dXVpZDpwYXNz_basic dXVpZDpwYXNz", "basic key12=[REDACTED] basic [REDACTED]"},
		// A value with no credential is untouched: the join alone must
		// not turn prose into one.
		{"authorization: Negotiate=algorithm", "authorization: Negotiate=algorithm"},
		{"authorization: key=value", "authorization: key=value"},
		{"authorization: id2=user123", "authorization: id2=user123"},
	}
	for _, tt := range tests {
		got := stripSecrets(tt.in)
		if got != tt.want {
			t.Errorf("stripSecrets(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

// TestStripSecretsBasicAuthTailInteriorGone pins that credential material
// carried inside a captured tail is redacted before the tail is re-emitted
// (#217). The tail's character class swallows whole credential segments and
// ReplaceAll cannot rescan what it emitted, so material ahead of the
// trailing scheme word would survive every later pass and reach the digest.
func TestStripSecretsBasicAuthTailInteriorGone(t *testing.T) {
	for _, in := range []string{
		"authorization: Zm9vOmJhcg==.dXNlcjpwYXNz.basic",
		"basic Zm9vOmJhcg==.dXNlcjpwYXNz.basic",
		"authorization: Zm9vOmJhcg==.dXNlcjpwYXNz.authorization: Basic dXVpZDpwYXNz",
	} {
		got := stripSecrets(in)
		if strings.Contains(got, "dXNlcjpwYXNz") {
			t.Errorf("stripSecrets(%q) = %q; basic-auth payload survived in the tail", in, got)
		}
	}
	// A JWT behind the scheme word goes with the rest of the tail: not one
	// segment of it may survive.
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.fakesigvalue1234"
	in := "authorization: Basic " + jwt + ".basic"
	got := stripSecrets(in)
	for _, seg := range []string{"eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJmYWtlIn0", "fakesigvalue1234"} {
		if strings.Contains(got, seg) {
			t.Errorf("stripSecrets(%q) = %q; JWT segment %q survived", in, got, seg)
		}
	}
}

// TestStripSecretsBasicAuthDeepTailChainTerminates pins that the fixed-point
// loop converges on a 500-deep chain: every ".basic <credential>" link is
// one more unit of work, so the loop has to keep passing until the whole
// chain is redacted and then stop. The measured output is "basic
// [REDACTED]" followed by ".basic [REDACTED]" once per link, 8516 bytes in
// all.
func TestStripSecretsBasicAuthDeepTailChainTerminates(t *testing.T) {
	const links = 500
	in := "basic dXNlcjpwYXNz" + strings.Repeat(".basic dXVpZDpwYXNz", links)
	want := "basic [REDACTED]" + strings.Repeat(".basic [REDACTED]", links)
	got := stripSecrets(in)
	if got != want {
		t.Errorf("stripSecrets(chain of %d links) = %d bytes with %d redactions; want %d bytes with %d redactions",
			links, len(got), strings.Count(got, "[REDACTED]"), len(want), strings.Count(want, "[REDACTED]"))
	}
	if len(got) != 8516 {
		t.Errorf("stripSecrets(chain of %d links) = %d bytes; want 8516", links, len(got))
	}
}

// TestSafeTail pins safeTail's contract: what it returns is safe to
// re-emit, and it fails closed. A tail that is exactly a scheme word is
// emitted unchanged, because the next credential needs that word (#216); a
// tail that stops on a scheme word loses everything ahead of it; a tail that
// stops on no scheme word carries material too and is redacted whole.
func TestSafeTail(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		// Material ahead of the scheme word goes, and with it the
		// separator that would otherwise introduce it.
		{"dXNlcjpwYXNz.basic", "[REDACTED].basic"},
		{".dXNlcjpwYXNz.basic", ".[REDACTED].basic"},
		// The tail is exactly the scheme word: unchanged (#216).
		{".basic", ".basic"},
		{".basic.basic", ".[REDACTED].basic"},
		// No scheme word: redacted whole, fail closed.
		{"dXNlcjpwYXNz", "[REDACTED]"},
		{"", "[REDACTED]"},
	}
	for _, tt := range tests {
		if got := safeTail(tt.in); got != tt.want {
			t.Errorf("safeTail(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

// TestStripSecretsBasicAuthIdempotent pins that redacting an already
// redacted line changes nothing: the digest is rendered from text that has
// been through stripSecrets more than once.
func TestStripSecretsBasicAuthIdempotent(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.fakesigvalue1234"
	for _, in := range []string{
		"authorization: Basic dXNlcjpwYXNz",
		"basic dXNlcjpwYXNz",
		"basic authentication failed",
		"authorization: Basic " + jwt,
		"basic " + jwt,
		"Basic dXNlcjpwYXNz%3Dextra",
		"basic dXNlcjpwYXNz.basic dXVpZDpwYXNz",
		"authorization: Basic dXNlcjpwYXNz.basic dXVpZDpwYXNz",
		"basic dXNlcjpwYXNz%3Dbasic dXVpZDpwYXNz",
		"basic dXNlcjpwYXNz%3D.authorization dXVpZDpwYXNz",
		"basic dXNlcjpwYXNz%3abasic dXVpZDpwYXNz",
		"basic dXNlcjpwYXNz%3fbasic dXVpZDpwYXNz",
		"basic dXNlcjpwYXNz%20basic dXVpZDpwYXNz",
		"%3Dbasic%20dXNlcjpwYXNz",
		"0basic%20dXNlcjpwYXNz",
		"authorization dXVpZDpwYXNz",
		"Authorization-foo.Authorization:dXNlcjpwYXNz",
		"failed with basic dXNlcjpwYXNz in request",
		"basic dXNlcjpwYXNz and dXVpZDpwYXNz",
		"basic dXNlcjpwYXNz=basic dXVpZDpwYXNz",
		"basic%20dXNlcjpwYXNz in request",
		"BASIC dXNlcjpwYXNz in request",
		"basic dXNlcjpwYXNz== and more",
		"authorization: Zm9vOmJhcg==.dXNlcjpwYXNz.basic",
		"basic Zm9vOmJhcg==.dXNlcjpwYXNz.basic",
		"authorization: Basic " + jwt + ".basic",
		"basic Zm9vOmJhcg==.dXNlcjpwYXNz.basic dXVpZDpwYXNz",
		"authorization: Basic Zm9vOmJhcg==.dXNlcjpwYXNz.basic dXVpZDpwYXNz",
		`{"authorization": "Basic Zm9vOmJhcg==.dXNlcjpwYXNz.basic"}`,
		"basic dXVpZDpwYXNzbasic dXVpZDpwYXNz",
		"basic dXNlcjE6cA=basic dXVpZDpwYXNz",
		"authorization: dXVpZDpwYXNzbasic authorization dXVpZDpwYXNz",
		// A credential glued to a following token by "=" (issue #230).
		"basic Zm9vOmJhcg=request",
		"basic Zm9vOmJhcg=trailing",
		"basic%20Zm9vOmJhcg=request",
		"basic auth Zm9vOmJhcg=request",
		"basic YWRtaW46YWRtaW4==trailing",
		"authorization: Basic Zm9vOmJhcg=request",
		"basic auth=failed",
		"basic key=value",
		"basic key1=value",
		"basic Zm9vOmJhcg=request.basic dXVpZDpwYXNz",
		"basic Zm9vOmJhcg=request.dXNlcjpwYXNz",
		"basic abc1=Zm9vOmJhcg",
		"basic key1=Zm9vOmJhcg",
		"basic x9=Ym9vdGFpbjpzZWNyZXQ",
		"basic Zm9vOmJhcg=Zm9vOmJhcg",
		"basic id2=user123",
		// A gate-failing "=" segment with a glued scheme word or a leading
		// glue run (issue #259): the segment cut re-emits the word, and the
		// glue stays where the line carried it.
		"authorization: dXNlcjpwYXNz=dXVpZDpwYXNzbasic",
		"authorization: dXNlcjpwYXNz=-dXVpZDpwYXNz",
		"basic dXNlcjE6cA=dXVpZDpwYXNzbasic",
		"basic dXNlcjE6cA=-dXVpZDpwYXNz",
		"authorization: Negotiate.dXNlcjpwYXNz.basic",
		"authorization: Negotiate.dXNlcjpwYXNz",
		"basic Basic.dXNlcjpwYXNz.basic",
		"authorization: Negotiate.dXNlcjpwYXNz%3adXVpZDpwYXNz",
		"authorization: Negotiate.key=dXNlcjpwYXNz",
		// The "+/-glued" and mid-run shapes (issue #240).
		"Basic: Zm9vOmJhcg==+authorization dXNlcjE6cA=",
		"authorization: dXVpZDpwYXNzauthorization=dXVpZDpwYXNz",
		"basic dXVpZDpwYXNzbasic-dXNlcjpwYXNz",
		"basic Zm9vOmJhcg+basic-dXNlcjpwYXNz",
		"basic subbasic",
		"basic sub-basic-dXNlcjpwYXNz",
		// A credential folded into a declined header value by "=" (#246).
		"authorization: Negotiate=dXNlcjpwYXNz",
		"authorization: dXNlcjpwYXNz=key=dXVpZDpwYXNz",
		"authorization: Negotiate=dXNlcjpwYXNz.dXVpZDpwYXNz",
		"authorization: Negotiate=dXNlcjpwYXNzd29yZA==",
		"authorization: key=dXVpZDpwYXNz_basic dXVpZDpwYXNz",
		"basic key12=dXVpZDpwYXNz_basic dXVpZDpwYXNz",
	} {
		once := stripSecrets(in)
		if twice := stripSecrets(once); twice != once {
			t.Errorf("stripSecrets(%q) = %q; second pass = %q", in, once, twice)
		}
	}
}

// TestStripSecretsBasicAuthLayerInteraction pins that both redaction layers
// act on a single line: the basic-auth layer and the secretPatterns layer
// (which runs after it), each stripping its own secret and leaving the other
// layer's "[REDACTED]" marker in place.
func TestStripSecretsBasicAuthLayerInteraction(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.fakesigvalue1234"
	tests := []struct {
		in, want string
	}{
		{"password=s3cret authorization: Basic " + jwt, "[REDACTED] authorization: [REDACTED]"},
		{"token=abc123 basic dXNlcjpwYXNz%3Dextra", "[REDACTED] basic [REDACTED]"},
		{"authorization: Basic dXNlcjpwYXNz token=abc123", "authorization: [REDACTED] [REDACTED]"},
	}
	for _, tt := range tests {
		if got := stripSecrets(tt.in); got != tt.want {
			t.Errorf("stripSecrets(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

// TestStripSecretsBasicAuthGluedWordInDecodedRun pins #242: a scheme word
// glued to a credential with base64-alphabet glue sits inside the run that
// passes the decode gate, so wholesale redaction swallows the word and
// orphans the credential behind it, which then keeps its plaintext. The word
// is cut out of that run and re-emitted with a real space, which is the
// context the following credential is read with.
func TestStripSecretsBasicAuthGluedWordInDecodedRun(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		// The word is glued with "+": the whole run decodes to a credential,
		// the gate passes, and the word inside it is cut out and re-emitted,
		// so the second credential is read and redacted on the next pass.
		{"basic dXVpZDpwYXNz+basic dXNlcjE6cA=", "basic [REDACTED] basic [REDACTED]"},
		// "_" glue: same shape, same cut.
		{"basic dXVpZDpwYXNz_basic dXNlcjE6cA=", "basic [REDACTED] basic [REDACTED]"},
		// The header form consumes the value on the header's context, but the
		// word glued inside it is still cut out for the credential behind it.
		{"authorization: dXVpZDpwYXNzbasic/ dXNlcjpwYXNz", "authorization: [REDACTED] basic [REDACTED]"},
		// Three credentials: the cut lands on the first, the second is
		// redacted on the next pass, and its tail re-emits the third's scheme
		// word as context, so the third is redacted too. The trailing
		// ".basic" is that context, kept by safeTail; once the credential it
		// names is already "[REDACTED]" it is inert, so it stays rather than
		// being stripped a second time.
		{"basic dXNlcjpwYXNz+basic dXVpZDpwYXNz.basic dXNlcjE6cA=", "basic [REDACTED] basic [REDACTED].basic [REDACTED]"},
		// "-" is a word-chain character, so the word lands in the tolerated
		// word chain rather than the core. The word chain is judged per run
		// and redacted whole, so the word does not re-emit here; every
		// payload still goes, and the leading scheme word plus the safeTail
		// context keep any following credential covered.
		{"basic dXVpZDpwYXNz-basic dXNlcjE6cA=", "basic [REDACTED] [REDACTED]"},
		// A digit glued after the word makes the remainder undecodable, so no
		// cut: cutting would ship the credential behind it in plaintext. The
		// run keeps its wholesale redaction, as before the cut arm.
		{"basic dXVpZDpwYXNz+basic12dXNlcjpwYXNz", "basic [REDACTED]"},
		// The mirror case: the remainder behind the word still decodes to a
		// credential, so the cut is taken — the word is re-emitted and the
		// remainder is redacted on the next pass.
		{"basic dTpwbasic+dTpw", "basic [REDACTED] basic [REDACTED]"},
		// Prose: nothing decodes to a user:password pair, so the line is
		// byte-identical.
		{"subbasic", "subbasic"},
		{"basic authorization", "basic authorization"},
		{"basic authentication failed", "basic authentication failed"},
	}
	for _, tt := range tests {
		if got := stripSecrets(tt.in); got != tt.want {
			t.Errorf("stripSecrets(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
	// The cut re-emits a scheme word, so a second pass must leave the output
	// unchanged: the digest is rendered from text already through the
	// function once.
	for _, tt := range tests {
		once := stripSecrets(tt.in)
		if twice := stripSecrets(once); twice != once {
			t.Errorf("stripSecrets(%q) = %q; second pass = %q", tt.in, once, twice)
		}
	}
	// Whatever the context words do, no credential payload may reach the
	// digest.
	for _, tt := range tests {
		got := stripSecrets(tt.in)
		for _, p := range []string{"dXVpZDpwYXNz", "dXNlcjpwYXNz", "dXNlcjE6cA", "dTpw"} {
			if strings.Contains(got, p) {
				t.Errorf("stripSecrets(%q) = %q; payload %q survived", tt.in, got, p)
			}
		}
	}
}

func TestFetchPodLogs_empty(t *testing.T) {
	k := &kube{}
	got, _ := k.fetchPodLogs(context.Background(), nil, DefaultPodLogConcurrency)
	if got != nil {
		t.Errorf("expected nil for empty pods, got %v", got)
	}
	got, _ = k.fetchPodLogs(context.Background(), []podLogSpec{}, DefaultPodLogConcurrency)
	if got != nil {
		t.Errorf("expected nil for empty slice, got %v", got)
	}
}

// TestNormalizePodLogConcurrency pins the three branches of the normaliser:
// unset or non-positive falls back to the default, a positive value passes
// through unchanged, and anything over the 8-pod cap is clamped. The cap is
// the file-level invariant that a misconfiguration can never open more
// concurrent log reads than a group can name (issue #146), so it must hold
// at the function boundary and not just inside Enrich's path.
func TestNormalizePodLogConcurrency(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{"negative falls back to default", -3, DefaultPodLogConcurrency},
		{"zero falls back to default", 0, DefaultPodLogConcurrency},
		{"positive one passes through", 1, 1},
		{"positive default passes through", DefaultPodLogConcurrency, DefaultPodLogConcurrency},
		{"positive seven passes through", 7, 7},
		{"eight is the upper bound, passes through", 8, 8},
		{"nine clamps to eight", 9, 8},
		{"large value clamps to eight", 1000, 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizePodLogConcurrency(tt.in); got != tt.want {
				t.Errorf("normalizePodLogConcurrency(%d) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestFetchPodLogs_badKey(t *testing.T) {
	// podLogSpec has no string key to be malformed: only the namespace/name
	// pair can fail. A nil Name still produces a key, so test the empty-spec
	// path here too.
	k := &kube{}
	got, _ := k.fetchPodLogs(context.Background(), []podLogSpec{{Namespace: "ns"}}, DefaultPodLogConcurrency)
	if len(got) != 0 {
		t.Errorf("expected empty map for empty Name, got %v", got)
	}
}

func TestFetchPodLogs_noServer(t *testing.T) {
	k := &kube{base: "http://127.0.0.1:1"}
	got, _ := k.fetchPodLogs(context.Background(), []podLogSpec{{Namespace: "ns", Name: "pod"}}, DefaultPodLogConcurrency)
	if len(got) != 0 {
		t.Errorf("expected empty map when server unreachable, got %v", got)
	}
}

func TestFetchPodLogs_success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/log") {
			http.Error(w, "not found", 404)
			return
		}
		q := r.URL.Query()
		if q.Get("previous") != "true" {
			http.Error(w, "expected previous=true", 400)
			return
		}
		w.Write([]byte("line1\nline2\nline3\n"))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL + "/", token: "tok", hc: http.DefaultClient}
	got, prov := k.fetchPodLogs(context.Background(), []podLogSpec{{Namespace: "ns", Name: "pod", Previous: true}}, DefaultPodLogConcurrency)
	if len(got) != 1 {
		t.Fatalf("expected 1 log, got %d", len(got))
	}
	if !strings.Contains(got["ns/pod"], "line1") {
		t.Errorf("log missing expected content: %q", got["ns/pod"])
	}
	if p := prov["ns/pod"]; p.Stream != "previous" {
		t.Errorf("provenance stream = %q, want previous", p.Stream)
	}
}

func TestFetchPodLogs_stripsSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("api_key=supersecret\nok line\n"))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL + "/", token: "tok", hc: http.DefaultClient}
	got, _ := k.fetchPodLogs(context.Background(), []podLogSpec{{Namespace: "ns", Name: "pod"}}, DefaultPodLogConcurrency)
	if len(got) != 1 {
		t.Fatalf("expected 1 log, got %d", len(got))
	}
	if strings.Contains(got["ns/pod"], "supersecret") {
		t.Errorf("secret not stripped: %q", got["ns/pod"])
	}
}

func TestFetchPodLogs_capped(t *testing.T) {
	big := strings.Repeat("x\n", 100)
	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.RawQuery
		w.Write([]byte(big))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL + "/", token: "tok", hc: http.DefaultClient}
	got, _ := k.fetchPodLogs(context.Background(), []podLogSpec{{Namespace: "ns", Name: "pod"}}, DefaultPodLogConcurrency)
	if len(got) != 1 {
		t.Fatalf("expected 1 log, got %d", len(got))
	}
	if !strings.Contains(gotURL, "tailLines=20") {
		t.Errorf("expected tailLines=20 in request, got: %s", gotURL)
	}
}

// Regression for #146: fetchPodLogs used to walk the capped pods strictly in
// series, so one stalled read on pod 1 held the whole flush behind 8 × the
// per-pod timeout. With the bounded per-pod semaphore the remaining reads
// overlap the stall, so the function returns in ≈ 1 round-trip + the per-pod
// timeout floor — well under 8 ×. The timing gap is what the regression
// asserts (bounded ≈ 3 batches vs serial 3 + 7); the in-flight count asserts
// the bound is in force as an upper limit.
//
// The threshold is a generous ceiling on the bounded path so a slow CI host
// under load does not flake the test. The shape — never 8 × the per-pod
// timeout — is what the regression is meant to lock in.
func TestFetchPodLogsStalledPodDoesNotSerialise(t *testing.T) {
	const (
		cost = 200 * time.Millisecond // each healthy per-pod read's cost
		// Bounded dispatch: the stall (cost * 3 = the http.Client
		// timeout) overlaps with the other reads, so the total is ≈
		// one timeout + three batches of cost ≈ 4 × cost in practice.
		// Serial dispatch: the stall (one per-pod timeout) plus every
		// read behind it ≈ (3 + 7) × cost. The threshold sits at
		// 8 × cost, comfortably above the bounded shape and well
		// below the serial one.
		threshold = 8 * cost
	)

	var inFlight, maxInFlight atomic.Int32
	stall := make(chan struct{})

	// Track the peak number of concurrently in-flight log reads, including
	// the stalled one.
	updateMax := func() {
		n := inFlight.Add(1)
		for {
			m := maxInFlight.Load()
			if n <= m || maxInFlight.CompareAndSwap(m, n) {
				break
			}
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/log") {
			http.NotFound(w, r)
			return
		}
		defer inFlight.Add(-1)
		updateMax()
		if strings.Contains(r.URL.Path, "/pods/p1/log") {
			// The stalled read: blocks until the test closes the channel
			// on the way out.
			<-stall
			return
		}
		// A healthy read costs one round-trip, so the serial walk pays it
		// per pod.
		time.Sleep(cost)
		w.Write([]byte("ok\n"))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, token: "tok", hc: &http.Client{Timeout: cost * 3}}
	pods := []podLogSpec{
		{Namespace: "ns", Name: "p1"},
		{Namespace: "ns", Name: "p2"},
		{Namespace: "ns", Name: "p3"},
		{Namespace: "ns", Name: "p4"},
		{Namespace: "ns", Name: "p5"},
		{Namespace: "ns", Name: "p6"},
		{Namespace: "ns", Name: "p7"},
		{Namespace: "ns", Name: "p8"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer close(stall) // wake the stalled handler before the server tears down

	start := time.Now()
	done := make(chan map[string]string, 1)
	go func() {
		got, _ := k.fetchPodLogs(ctx, pods, DefaultPodLogConcurrency)
		done <- got
	}()

	select {
	case got := <-done:
		elapsed := time.Since(start)
		if elapsed > threshold {
			t.Fatalf("fetchPodLogs took %v, past the bounded threshold %v; the stalled pod serialised the remaining reads",
				elapsed, threshold)
		}
		// The stalled pod is absent; every other pod is present.
		if len(got) != 7 {
			t.Fatalf("expected logs for 7 healthy pods, got %d: %v", len(got), got)
		}
		if _, ok := got["ns/p1"]; ok {
			t.Errorf("stalled pod p1 must not appear in the results")
		}
	case <-time.After(threshold + 3*cost):
		t.Fatal("fetchPodLogs did not return within the bounded threshold; the stalled pod serialised the remaining reads")
	}

	// The bound must be in force: never more than 4 reads in flight at once.
	if max := maxInFlight.Load(); max > DefaultPodLogConcurrency {
		t.Errorf("more than %d reads in flight (observed %d); the per-pod bound is not in force",
			DefaultPodLogConcurrency, max)
	}
}

// Regression: 0.1.8 compared the group's cluster against a client cluster that
// was never assigned, so every group looked foreign and enrichment was skipped
// on every instance. 77 digests shipped narrating alert text alone while
// claiming the cluster was healthy. An unknown client cluster must enrich, not
// refuse.
func TestEnrichSkipsOnlyWhenBothClustersAreKnownAndDiffer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()

	tests := []struct {
		name          string
		clientCluster string
		groupCluster  string
		wantSkipped   bool
	}{
		{"client cluster unknown enriches", "", "main", false},
		{"alert carries no cluster label enriches", "main", "", false},
		{"neither known enriches", "", "", false},
		{"same cluster enriches", "main", "main", false},
		{"known and different is skipped", "main", "utility", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &kube{cluster: tt.clientCluster, base: srv.URL, token: "tok", hc: srv.Client()}
			g := Group{Key: "single/A", Cluster: tt.groupCluster, Alerts: []Alert{
				{Labels: map[string]string{"alertname": "A", "namespace": "llm"}},
			}}
			got := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

			skipped := strings.Contains(got.Scope, "cluster state unavailable")
			if skipped != tt.wantSkipped {
				t.Errorf("skipped = %v, want %v (scope: %q)", skipped, tt.wantSkipped, got.Scope)
			}
		})
	}
}

func TestEnrichment_empty(t *testing.T) {
	got := Enrichment{}.empty()
	if !got {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestEnrich_skipsSucceededPodsAndSortsByScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(r.URL.Path, "/pods") || strings.Contains(r.URL.Path, "/log") {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		_, _ = io.WriteString(w, `{"items":[
			{"metadata":{"name":"job-finished","namespace":"ns1"},
			 "status":{"phase":"Succeeded",
			   "containerStatuses":[{"ready":false,"restartCount":0,
			     "state":{"terminated":{"reason":"Completed"}}}]}},
			{"metadata":{"name":"flaky-restart","namespace":"ns1"},
			 "status":{"phase":"Running",
			   "containerStatuses":[{"ready":false,"restartCount":1,
			     "state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}},
			{"metadata":{"name":"pending-pod","namespace":"ns1"},
			 "status":{"phase":"Pending",
			   "containerStatuses":[{"ready":false,"restartCount":0,
			     "state":{"waiting":{"reason":"ImagePullBackOff"}}}]}},
			{"metadata":{"name":"job-finished-2","namespace":"ns1"},
			 "status":{"phase":"Succeeded",
			   "containerStatuses":[{"ready":false,"restartCount":0,
			     "state":{"terminated":{"reason":"Completed"}}}]}}
		]}`)
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubePodNotReady", "namespace": "ns1"}}},
		Namespaces: []string{"ns1"},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	for _, p := range en.UnhealthyPods {
		if strings.Contains(p, "job-finished") {
			t.Errorf("Succeeded pod should be skipped, got %q", p)
		}
	}
	if len(en.UnhealthyPods) != 2 {
		t.Fatalf("expected 2 unhealthy pods (CrashLoopBackOff + Pending), got %d: %v", len(en.UnhealthyPods), en.UnhealthyPods)
	}
	if !strings.Contains(en.UnhealthyPods[0], "flaky-restart") {
		t.Errorf("expected worst pod (CrashLoopBackOff) first, got %v", en.UnhealthyPods)
	}
	if !strings.Contains(en.UnhealthyPods[1], "pending-pod") {
		t.Errorf("expected Pending pod second, got %v", en.UnhealthyPods)
	}
}

// TestResolveRepoPathsFluxKustomization exercises the Flux Kustomization
// → GitRepository path. The kube is wired to a test server that returns
// matching Kustomization and GitRepository specs.
func TestResolveRepoPathsFluxKustomization(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/"):
			_, _ = io.WriteString(w, `{"spec":{"path":"clusters/staging","sourceRef":{"name":"flux-system","kind":"GitRepository"}}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/staging-repo"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{{
		Name:      "p1",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "flux-system",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	cfg := &Config{}
	got := k.resolveRepoPaths(context.Background(), pods, cfg)
	if len(got) != 1 {
		t.Fatalf("expected 1 resolved path, got %#v", got)
	}
	if got[0] != "https://github.com/example/staging-repo/clusters/staging" {
		t.Fatalf("unexpected entry: %q", got[0])
	}
}

// TestResolveRepoPathsFluxPath exercises the fluxPath branch via
// resolveRepoPaths: the pod carries both the kustomize.toolkit.fluxcd.io/name
// and the kustomize.toolkit.fluxcd.io/namespace annotations, so resolveRepoPaths
// routes the lookup through k.fluxPath(annotation-ns, kustomization-name) and
// resolves the repo+path from the Kustomization + GitRepository pair.
func TestResolveRepoPathsFluxPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/payments","sourceRef":{"name":"payments-repo","kind":"GitRepository"}}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/payments"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{{
		Name:      "p2",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "payments",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	got := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 1 || got[0] != "https://github.com/example/payments/apps/payments" {
		t.Fatalf("unexpected paths: %#v", got)
	}
}

// TestResolveRepoPathsMissingKustomization asserts that when a pod carries
// the Flux annotations but the referenced Kustomization is missing (the
// API returns 404), resolveRepoPaths still ships (returns cleanly
// without error) and no spurious GitOps path is attached. This is the
// regression test for #92: the now-removed fluxHelmPath "Helm release"
// rescue branch would have re-issued an identical fluxPath call against
// the same kustomization+namespace, fabricating a hit count of two for
// the kustomization lookup and masking the failure.
func TestResolveRepoPathsMissingKustomization(t *testing.T) {
	var kuzHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/ghost-payments"):
			// Simulate the Kustomization being absent.
			kuzHits++
			http.NotFound(w, r)
		default:
			t.Errorf("unexpected API hit for %s; resolveRepoPaths must not retry after a 404", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	// Pod carries the Flux annotations, but the Kustomization does not
	// exist in the cluster (404). The digest must still ship and the
	// function must return without attaching a fabricated GitOps path.
	pods := []podRef{{
		Name:      "p2",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "ghost-payments",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	got := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 0 {
		t.Fatalf("expected no GitOps paths when Kustomization is missing, got: %#v", got)
	}
	// fluxHelmPath used to make a second, identical kustomization lookup
	// that always failed identically. Pin this contract: the
	// kustomization endpoint is hit at most once.
	if kuzHits > 1 {
		t.Fatalf("expected at most one kustomization lookup after 404, got %d", kuzHits)
	}
	if kuzHits == 0 {
		t.Fatalf("expected the kustomization lookup to be attempted once, got 0")
	}
}

// TestResolveRepoPathsArgoApplication exercises the ArgoCD branch: the
// pod carries an argocd.argoproj.io/instance annotation, and the API
// returns a matching Application spec.
func TestResolveRepoPathsArgoApplication(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"spec":{"source":{"repoURL":"https://github.com/example/argo","path":"manifests/web"}}}`)
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{{
		Name:      "p3",
		Namespace: "ns-b",
		Annotations: map[string]string{
			"argocd.argoproj.io/instance": "guestbook",
		},
	}}
	got := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 1 || got[0] != "https://github.com/example/argo/manifests/web" {
		t.Fatalf("unexpected paths: %#v", got)
	}
}

// TestResolveRepoPathsGitOpsFallback exercises the GITOPS_REPO +
// GITOPS_PATH fallback: pods without GitOps annotations but with the
// fallback configured should still resolve to a repo path.
func TestResolveRepoPathsGitOpsFallback(t *testing.T) {
	// No server should be hit for this branch — the API would 404 but
	// we'd notice.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API hit for %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{{Name: "plain", Namespace: "ns", Annotations: map[string]string{}}}
	cfg := &Config{GitOpsRepo: "https://github.com/example/fallback", GitOpsPath: "deploy/staging"}
	got := k.resolveRepoPaths(context.Background(), pods, cfg)
	if len(got) != 1 || got[0] != "https://github.com/example/fallback/deploy/staging" {
		t.Fatalf("unexpected fallback paths: %#v", got)
	}
}

// TestResolveRepoPathsEmpty exercises the empty-result case: no pods, or
// pods with no annotations and no fallback configured.
func TestResolveRepoPathsEmpty(t *testing.T) {
	k := &kube{}
	if got := k.resolveRepoPaths(context.Background(), nil, &Config{}); got != nil {
		t.Fatalf("expected nil, got %#v", got)
	}
	cfg := &Config{}
	if got := k.resolveRepoPaths(context.Background(), []podRef{{Annotations: map[string]string{}}}, cfg); got != nil {
		t.Fatalf("expected nil when nothing resolves and no fallback configured, got %#v", got)
	}
}

// fluxKustomizationAPIHarness serves one Kustomization (by name, when
// kuzJSON is non-empty) and one GitRepository (when repoJSON is non-empty).
// A null Kustomization simulates the object being absent.
func fluxKustomizationAPIHarness(t *testing.T, kuzName, kuzJSON, repoJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/kustomizations/") {
			if kuzJSON == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, kuzJSON)
			return
		}
		if strings.Contains(r.URL.Path, "/gitrepositories/") {
			if repoJSON == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, repoJSON)
			return
		}
		http.NotFound(w, r)
	}))
}

func fluxAnnotatedPod(name, ns, kuz, kuzNs string) []podRef {
	ann := map[string]string{"kustomize.toolkit.fluxcd.io/name": kuz}
	if kuzNs != "" {
		ann["kustomize.toolkit.fluxcd.io/namespace"] = kuzNs
	}
	return []podRef{{Name: name, Namespace: ns, Annotations: ann}}
}

// TestResolveKustomizationTopologyWithComponentsAndDependencies is the
// motivating case: the resolved Kustomization pulls in a reusable component
// and a dependency, so the topology record must surface all three: the
// Kustomization name, its source/path, the component paths as declared, and
// the dependsOn names (with any foreign namespace made explicit).
func TestResolveKustomizationTopologyWithComponentsAndDependencies(t *testing.T) {
	srv := fluxKustomizationAPIHarness(t, "web",
		`{"spec":{"path":"apps/web","sourceRef":{"kind":"GitRepository","name":"main","namespace":"flux-system"},
		 "components":["../base/common"],
		 "dependsOn":[{"name":"base-common"},{"name":"db","namespace":"databases"}]}}`,
		`{"spec":{"url":"https://github.com/example/web"}}`)
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("web-0", "apps", "web", ""))
	if len(got) != 1 {
		t.Fatalf("expected exactly one topology record, got %#v", got)
	}
	rec := got[0]
	for _, want := range []string{
		"kustomization apps/web (path: apps/web)",
		"GitRepository/main (flux-system)",
		"components: ../base/common",
		"dependsOn: base-common, databases/db",
	} {
		if !strings.Contains(rec, want) {
			t.Errorf("record missing %q: %s", want, rec)
		}
	}
}

// TestResolveKustomizationTopologyNoComposition covers a Kustomization with
// no spec.components and no spec.dependsOn: both subsections render as an
// explicit "none declared" rather than being silently dropped, and the
// sourceRef without an explicit kind renders under its default kind.
func TestResolveKustomizationTopologyNoComposition(t *testing.T) {
	srv := fluxKustomizationAPIHarness(t, "bare",
		`{"spec":{"path":"apps/bare","sourceRef":{"kind":"GitRepository","name":"main"}}}`,
		`{"spec":{"url":"https://github.com/example/bare"}}`)
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("bare-0", "apps", "bare", ""))
	if len(got) != 1 {
		t.Fatalf("expected exactly one topology record, got %#v", got)
	}
	rec := got[0]
	for _, want := range []string{"kustomization apps/bare (path: apps/bare)", "components: none declared", "dependsOn: none declared"} {
		if !strings.Contains(rec, want) {
			t.Errorf("record missing %q: %s", want, rec)
		}
	}
}

// TestResolveKustomizationTopologyFailedLookup is the lookup-failure case:
// the pod carries the Flux annotations but the Kustomization does not exist
// (404). The function must return no record at all — not a record with "none"
// subsections, which would claim the spec was read and found nothing.
func TestResolveKustomizationTopologyFailedLookup(t *testing.T) {
	srv := fluxKustomizationAPIHarness(t, "ghost", "", "")
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("p", "ns", "ghost", ""))
	if len(got) != 0 {
		t.Fatalf("expected no topology record when the Kustomization is missing, got %#v", got)
	}
}

// TestResolveKustomizationTopologyScopedToResolvedWorkload asserts the record
// follows the pod's own Kustomization annotation: other Kustomizations in the
// namespace are never read, and two pods resolving to the same Kustomization
// yield one record, not two.
func TestResolveKustomizationTopologyScopedToResolvedWorkload(t *testing.T) {
	var kuzGets []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/kustomizations/") {
			name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			kuzGets = append(kuzGets, name)
			if name == "web" {
				_, _ = io.WriteString(w, `{"spec":{"path":"apps/web","sourceRef":{"kind":"GitRepository","name":"main"}},"components":null,"dependsOn":null}`)
				return
			}
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.URL.Path, "/gitrepositories/") {
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/web"}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{
		{Name: "web-0", Namespace: "apps", Annotations: map[string]string{"kustomize.toolkit.fluxcd.io/name": "web"}},
		// A second pod resolving to the same Kustomization.
		{Name: "web-1", Namespace: "apps", Annotations: map[string]string{"kustomize.toolkit.fluxcd.io/name": "web"}},
		// A third pod whose annotations name a Kustomization that does not
		// exist in the cluster.
		{Name: "stray", Namespace: "apps", Annotations: map[string]string{"kustomize.toolkit.fluxcd.io/name": "unrelated"}},
	}
	got := k.resolveKustomizationTopology(context.Background(), pods)
	if len(got) != 1 {
		t.Fatalf("expected exactly one record (deduped), got %#v", got)
	}
	if !strings.Contains(got[0], "kustomization apps/web") {
		t.Fatalf("record must be for the resolved Kustomization, got %q", got[0])
	}
	// Only the Kustomizations the pods actually resolved to may be read,
	// and at most once each (deduped): two pods resolving to "web" cost
	// one GET, and "unrelated" costs the single failed GET it always will.
	counts := map[string]int{}
	for _, n := range kuzGets {
		counts[n]++
	}
	if len(kuzGets) != 2 || counts["web"] != 1 || counts["unrelated"] != 1 {
		t.Fatalf("kustomization GETs = %v, want web=1 and unrelated=1", kuzGets)
	}
}

// TestResolveKustomizationTopologyOciComponent covers a component that is not
// a relative path: the value is quoted as-is under its own label, so the
// record never presents it as a path this service resolved or read.
func TestResolveKustomizationTopologyOciComponent(t *testing.T) {
	srv := fluxKustomizationAPIHarness(t, "oci",
		`{"spec":{"path":"apps/oci","sourceRef":{"kind":"GitRepository","name":"main"},"components":["oci://registry.example.com/base"]}}`,
		`{"spec":{"url":"https://github.com/example/oci"}}`)
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("oci-0", "apps", "oci", ""))
	if len(got) != 1 {
		t.Fatalf("expected exactly one topology record, got %#v", got)
	}
	if !strings.Contains(got[0], "components: oci://registry.example.com/base") {
		t.Errorf("component must be rendered verbatim under its own label: %s", got[0])
	}
}

// TestResolveKustomizationTopologyRejectsUnsafePaths asserts sanitiser
// parity with resolveRepoPaths: the same class of value (a path-like field
// quoted from a cluster object) is dropped on the same hostile character set
// — NUL, backslash, percent — the survivors render verbatim, and the record
// is flattened and fence-inert at construction. Unlike resolveRepoPaths, no
// path.Clean runs here, so a legitimate `..` segment in a surviving
// component is preserved.
func TestResolveKustomizationTopologyRejectsUnsafePaths(t *testing.T) {
	// The JSON is a raw string so the hostile bytes arrive through JSON
	// escapes: \u0000 decodes to NUL, \\ to a single backslash, % is
	// literal.
	srv := fluxKustomizationAPIHarness(t, "web",
		`{"spec":{"path":"apps\\web","sourceRef":{"kind":"GitRepository","name":"main","namespace":"flux-system"},
		 "components":["../base/common","pods\u0000evil","pods\\..\\..","pods%2F..%2F"],
		 "dependsOn":[{"name":"base-common"},{"name":"evil\\name","namespace":"apps"}]}}`,
		`{"spec":{"url":"https://github.com/example/web"}}`)
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("web-0", "apps", "web", ""))
	if len(got) != 1 {
		t.Fatalf("expected exactly one topology record, got %#v", got)
	}
	rec := got[0]
	// (b) The safe values survive verbatim, including the `..` segment a
	// path.Clean (deliberately not applied here) would have collapsed.
	for _, want := range []string{
		"components: ../base/common",
		"dependsOn: base-common",
	} {
		if !strings.Contains(rec, want) {
			t.Errorf("record missing %q: %s", want, rec)
		}
	}
	// (c) The unsafe spec.path renders an explicit refused marker instead of
	// vanishing: a refused path must not read as an absent one, and the
	// hostile value itself must not appear.
	if !strings.Contains(rec, "(path: refused)") {
		t.Errorf("refused spec.path must render a refused marker: %s", rec)
	}
	if strings.Contains(rec, `apps\web`) {
		t.Errorf("unsafe spec.path value leaked into the record: %s", rec)
	}
	// (c,d) Every hostile byte class, the percent-encoding forms
	// (case-insensitive), a newline, and a triple-dash run are absent.
	for _, hostile := range []string{"\x00", `\`, "\n", "---"} {
		if strings.Contains(rec, hostile) {
			t.Errorf("record carries hostile value %q: %s", hostile, rec)
		}
	}
	if lower := strings.ToLower(rec); strings.Contains(lower, "%2f") || strings.Contains(lower, "%2e") {
		t.Errorf("percent-encoded traversal survived: %s", rec)
	}
	if strings.Contains(rec, "pods") {
		t.Errorf("unsafe component values leaked into the record: %s", rec)
	}
	if strings.Contains(rec, "evil") {
		t.Errorf("unsafe dependency name leaked into the record: %s", rec)
	}
}

// TestResolveKustomizationTopologyNoneSafeVersusNoneDeclared pins the
// explicit negative: a subsection whose declared values were all refused
// reads "none safe", while an empty spec reads "none declared" — two
// different findings that a shared "none" would collapse.
func TestResolveKustomizationTopologyNoneSafeVersusNoneDeclared(t *testing.T) {
	run := func(t *testing.T, kuzJSON string) string {
		t.Helper()
		srv := fluxKustomizationAPIHarness(t, "kuz", kuzJSON,
			`{"spec":{"url":"https://github.com/example/kuz"}}`)
		defer srv.Close()

		k := &kube{hc: srv.Client(), base: srv.URL}
		got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("p-0", "apps", "kuz", ""))
		if len(got) != 1 {
			t.Fatalf("expected exactly one topology record, got %#v", got)
		}
		return got[0]
	}
	t.Run("all components unsafe", func(t *testing.T) {
		rec := run(t, `{"spec":{"path":"apps/kuz","sourceRef":{"kind":"GitRepository","name":"main"},
			"components":["pods\u0000evil","pods\\..\\..","pods%2F..%2F"]}}`)
		if !strings.Contains(rec, "components: none safe") {
			t.Errorf("record must say none safe when every component was refused: %s", rec)
		}
		if strings.Contains(rec, "components: none declared") {
			t.Errorf("refused components must not read as undeclared: %s", rec)
		}
	})
	t.Run("none declared", func(t *testing.T) {
		rec := run(t, `{"spec":{"path":"apps/kuz","sourceRef":{"kind":"GitRepository","name":"main"}}}`)
		if !strings.Contains(rec, "components: none declared") {
			t.Errorf("record must say none declared for an empty components list: %s", rec)
		}
		if strings.Contains(rec, "components: none safe") {
			t.Errorf("an empty spec must not read as refused: %s", rec)
		}
	})
	t.Run("all dependencies unsafe", func(t *testing.T) {
		rec := run(t, `{"spec":{"path":"apps/kuz","sourceRef":{"kind":"GitRepository","name":"main"},
			"dependsOn":[{"name":"evil\\name"},{"name":"ok","namespace":"bad\\ns"}]}}`)
		if !strings.Contains(rec, "dependsOn: none safe") {
			t.Errorf("record must say none safe when every dependency was refused: %s", rec)
		}
		if strings.Contains(rec, "dependsOn: none declared") {
			t.Errorf("refused dependencies must not read as undeclared: %s", rec)
		}
	})
}

// TestResolveKustomizationTopologyRefusedSingularFields pins the singular
// half of the refused-value rule: a sourceRef name or a spec.path that
// fails the safe() check renders an explicit "refused" marker in its
// fragment, so a refused value is never indistinguishable from an absent
// one — the same distinction the list subsections already make with
// "none safe". A safe value keeps its exact composed fragment.
func TestResolveKustomizationTopologyRefusedSingularFields(t *testing.T) {
	run := func(t *testing.T, kuzJSON string) string {
		t.Helper()
		srv := fluxKustomizationAPIHarness(t, "kuz", kuzJSON,
			`{"spec":{"url":"https://github.com/example/kuz"}}`)
		defer srv.Close()

		k := &kube{hc: srv.Client(), base: srv.URL}
		got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("p-0", "apps", "kuz", ""))
		if len(got) != 1 {
			t.Fatalf("expected exactly one topology record, got %#v", got)
		}
		return got[0]
	}
	// The JSON is a raw string so the hostile bytes arrive through JSON
	// escapes: \u0000 decodes to NUL, \\ to a single backslash.
	t.Run("refused sourceRef name", func(t *testing.T) {
		rec := run(t, `{"spec":{"path":"apps/kuz","sourceRef":{"kind":"GitRepository","name":"main\u0000evil"}}}`)
		if !strings.Contains(rec, "source: refused") {
			t.Errorf("refused sourceRef name must render source: refused: %s", rec)
		}
		if strings.Contains(rec, "main") {
			t.Errorf("refused sourceRef name leaked into the record: %s", rec)
		}
		if strings.Contains(rec, "GitRepository/main") {
			t.Errorf("refused sourceRef must not compose a source fragment: %s", rec)
		}
		if strings.Contains(rec, "\x00") {
			t.Errorf("record carries a NUL byte: %s", rec)
		}
	})
	t.Run("refused spec.path", func(t *testing.T) {
		rec := run(t, `{"spec":{"path":"apps\\web","sourceRef":{"kind":"GitRepository","name":"main"}}}`)
		if !strings.Contains(rec, "(path: refused)") {
			t.Errorf("refused spec.path must render (path: refused): %s", rec)
		}
		if strings.Contains(rec, `apps\web`) {
			t.Errorf("refused spec.path value leaked into the record: %s", rec)
		}
	})
	t.Run("safe values render verbatim", func(t *testing.T) {
		rec := run(t, `{"spec":{"path":"apps/kuz","sourceRef":{"kind":"GitRepository","name":"main","namespace":"flux-system"}}}`)
		for _, want := range []string{"(path: apps/kuz)", "source: GitRepository/main (flux-system)"} {
			if !strings.Contains(rec, want) {
				t.Errorf("record missing %q: %s", want, rec)
			}
		}
	})
}

// TestResolveNodesPodLabelNoNodeLabel forces the pods-list lookup branch
// of ResolveNodes: the alert has a pod label but no node label, so the
// function must query the pods API to find the node.
func TestResolveNodesPodLabelNoNodeLabel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/pods") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"items":[{"metadata":{"name":"p1"},"spec":{"nodeName":"worker-1"}},{"metadata":{"name":"p2"},"spec":{"nodeName":"worker-2"}}]}`)
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	alerts := []Alert{
		{Fingerprint: "fp-1", Labels: map[string]string{"pod": "p1", "namespace": "ns-a"}},
		{Fingerprint: "fp-2", Labels: map[string]string{"pod": "p2", "namespace": "ns-a"}},
	}
	got := k.ResolveNodes(context.Background(), alerts)
	if got["fp-1"] != "worker-1" {
		t.Fatalf("expected fp-1 -> worker-1, got %q", got["fp-1"])
	}
	if got["fp-2"] != "worker-2" {
		t.Fatalf("expected fp-2 -> worker-2, got %q", got["fp-2"])
	}
}

// TestResolveNodesNodeLabelShortCircuit exercises the fast path: alerts
// that already carry a node label should not trigger the pods API.
func TestResolveNodesNodeLabelShortCircuit(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	alerts := []Alert{
		{Fingerprint: "fp-3", Labels: map[string]string{"node": "ctrl-1"}},
	}
	got := k.ResolveNodes(context.Background(), alerts)
	if got["fp-3"] != "ctrl-1" {
		t.Fatalf("expected fp-3 -> ctrl-1, got %q", got["fp-3"])
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("unexpected API hits when alert already has node label: %d", hits)
	}
}

// TestResolveNodesNilReceiver ensures the nil-receiver guard works.
func TestResolveNodesNilReceiver(t *testing.T) {
	var k *kube
	got := k.ResolveNodes(context.Background(), []Alert{{Fingerprint: "fp", Labels: map[string]string{"node": "x"}}})
	// Nil receiver on a node-labelled alert is allowed to return either
	// an empty map (the simple guard) or a populated map. Either is fine.
	if got["fp"] != "" && got["fp"] != "x" {
		t.Fatalf("nil receiver returned unexpected entry: %#v", got)
	}
}

// TestResolveRepoPathsEdgeCaseInputs exercises the elevated must-check
// for edge-case inputs that could lead to path injection if a future
// regression lets annotation values or GitOps config flow unchecked into
// the kube URL builder. Each case asserts the call does not panic and
// that the resulting entries do not smuggle a `..` traversal segment or
// a null byte into the URL that becomes a clickable Discord link.
func TestResolveRepoPathsEdgeCaseInputs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Distinguish the Kustomization lookup from the GitRepository
		// lookup so fluxPath receives both `spec.path` (from the
		// Kustomization) and `spec.url` (from the GitRepository) — the
		// only combination that makes fluxPath return (url, path, true).
		if strings.Contains(r.URL.Path, "/gitrepositories/") {
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/flux-helm"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"spec":{"path":"clusters/staging","sourceRef":{"name":"podinfo","kind":"GitRepository"}}}`)
	}))
	defer srv.Close()

	cases := []struct {
		name string
		ann  map[string]string
	}{
		{"dotdot", map[string]string{"kustomize.toolkit.fluxcd.io/name": "podinfo", "kustomize.toolkit.fluxcd.io/namespace": "../../etc"}},
		{"nullbyte", map[string]string{"kustomize.toolkit.fluxcd.io/name": "podinfo\x00evil", "kustomize.toolkit.fluxcd.io/namespace": "flux-system"}},
		{"absnamespace", map[string]string{"kustomize.toolkit.fluxcd.io/name": "podinfo", "kustomize.toolkit.fluxcd.io/namespace": "/etc/passwd"}},
		{"percentencoded", map[string]string{"kustomize.toolkit.fluxcd.io/name": "podinfo%2F..%2F..", "kustomize.toolkit.fluxcd.io/namespace": "flux-system"}},
		{"backslash", map[string]string{"kustomize.toolkit.fluxcd.io/name": "podinfo\\..\\..", "kustomize.toolkit.fluxcd.io/namespace": "flux-system"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("resolveRepoPaths panicked on %s: %v", tc.name, r)
				}
			}()
			k := &kube{hc: srv.Client(), base: srv.URL}
			pods := []podRef{{Name: "p", Namespace: "ns", Annotations: tc.ann}}
			got := k.resolveRepoPaths(context.Background(), pods, &Config{})
			t.Logf("%s -> %#v", tc.name, got)
			assertRepoURLsSafe(t, tc.name, got)
		})
	}

	t.Run("gitops_fallback_traversal", func(t *testing.T) {
		// GITOPS_PATH with `..` segments is a common misconfiguration.
		// The fallback must not panic, and the produced URL must not
		// contain an unescaped `..` segment — a clickable Discord link
		// that resolved to a directory the operator did not configure
		// would be a user-visible bug at 03:00. resolveRepoPaths
		// sanitises with path.Clean, so `../../etc/secrets` collapses
		// to `etc/secrets`.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("resolveRepoPaths panicked on traversal fallback: %v", r)
			}
		}()
		k := &kube{}
		cfg := &Config{GitOpsRepo: "https://github.com/example/fallback", GitOpsPath: "../../etc/secrets"}
		got := k.resolveRepoPaths(context.Background(), []podRef{{Name: "p", Namespace: "ns", Annotations: map[string]string{}}}, cfg)
		t.Logf("fallback -> %#v", got)
		assertRepoURLsSafe(t, "gitops_fallback_traversal", got)
		if len(got) != 1 {
			t.Fatalf("expected exactly one fallback entry, got %#v", got)
		}
		if got[0] != "https://github.com/example/fallback/etc/secrets" {
			t.Fatalf("traversal segments not collapsed: got %q", got[0])
		}
	})

	t.Run("gitops_fallback_nullbyte", func(t *testing.T) {
		// A null byte in GITOPS_PATH must not produce an entry at all;
		// the result would otherwise be a clickable link with a NUL
		// smuggled into the rendered URL.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("resolveRepoPaths panicked on null-byte fallback: %v", r)
			}
		}()
		k := &kube{}
		cfg := &Config{GitOpsRepo: "https://github.com/example/fallback", GitOpsPath: "pods\x00evil"}
		got := k.resolveRepoPaths(context.Background(), []podRef{{Name: "p", Namespace: "ns", Annotations: map[string]string{}}}, cfg)
		t.Logf("nullbyte fallback -> %#v", got)
		assertRepoURLsSafe(t, "gitops_fallback_nullbyte", got)
		if len(got) != 0 {
			t.Fatalf("gitops_fallback_nullbyte: expected entry to be omitted when GitOpsPath contains NUL, got %#v", got)
		}
	})

	t.Run("gitops_fallback_percentencoded", func(t *testing.T) {
		// Percent-encoded traversal such as `%2F..%2F` is not collapsed
		// by path.Clean and would be emitted verbatim. The sanitiser
		// must drop the entry rather than render an unsafe URL.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("resolveRepoPaths panicked on percent-encoded fallback: %v", r)
			}
		}()
		k := &kube{}
		cfg := &Config{GitOpsRepo: "https://github.com/example/fallback", GitOpsPath: "podinfo%2F..%2F.."}
		got := k.resolveRepoPaths(context.Background(), []podRef{{Name: "p", Namespace: "ns", Annotations: map[string]string{}}}, cfg)
		t.Logf("percentencoded fallback -> %#v", got)
		assertRepoURLsSafe(t, "gitops_fallback_percentencoded", got)
		if len(got) != 0 {
			t.Fatalf("gitops_fallback_percentencoded: expected entry to be omitted when GitOpsPath contains '%%', got %#v", got)
		}
	})

	t.Run("gitops_fallback_backslash", func(t *testing.T) {
		// Backslashes are Windows separators that path.Clean (a
		// Unix-style package) leaves untouched. The sanitiser must
		// drop the entry rather than emit a URL GitHub will 404.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("resolveRepoPaths panicked on backslash fallback: %v", r)
			}
		}()
		k := &kube{}
		cfg := &Config{GitOpsRepo: "https://github.com/example/fallback", GitOpsPath: `podinfo\..\..`}
		got := k.resolveRepoPaths(context.Background(), []podRef{{Name: "p", Namespace: "ns", Annotations: map[string]string{}}}, cfg)
		t.Logf("backslash fallback -> %#v", got)
		assertRepoURLsSafe(t, "gitops_fallback_backslash", got)
		if len(got) != 0 {
			t.Fatalf("gitops_fallback_backslash: expected entry to be omitted when GitOpsPath contains backslash, got %#v", got)
		}
	})

	// Absolute paths (e.g. `/etc/secrets`) — GitOpsPath is operator-supplied
	// and an absolute path would normally be a misconfiguration, but the
	// sanitiser must not emit a URL like `https://github.com/example/etc/secrets`
	// because that would route the operator to the wrong repo subtree. The
	// contract: leading slashes are stripped (joining onto the repo's
	// subtree), so the resulting URL lands on the same default branch
	// root as an operator who left GitOpsPath empty.
	t.Run("gitops_fallback_absolutepath", func(t *testing.T) {
		k := &kube{}
		cfg := &Config{GitOpsRepo: "https://github.com/example/fallback"}
		cfg.GitOpsPath = "/etc/secrets"
		pods := []podRef{{Namespace: "ns", Name: "pod"}}
		got := k.resolveRepoPaths(context.Background(), pods, cfg)
		if len(got) != 1 {
			t.Fatalf("gitops_fallback_absolutepath: want one entry, got %#v", got)
		}
		const want = "https://github.com/example/fallback/etc/secrets"
		if got[0] != want {
			t.Fatalf("gitops_fallback_absolutepath: leading-slash not stripped, want %q got %q", want, got[0])
		}
		assertRepoURLsSafe(t, "gitops_fallback_absolutepath", got)
	})
}

// assertRepoURLsSafe fails the test if any entry contains a null byte,
// an unescaped `..` traversal segment, a percent-encoded traversal
// segment (the literal substring `%2F` or `%2E` after percent-decoding
// by a URL consumer), or a backslash separator. These are the safety
// invariants the resolveRepoPaths sanitiser is responsible for: the
// output is rendered as a clickable link in the digest, and any of
// these would render a link the operator did not intend.
func assertRepoURLsSafe(t *testing.T, name string, entries []string) {
	t.Helper()
	for _, e := range entries {
		if strings.Contains(e, "\x00") {
			t.Fatalf("%s: entry contains null byte: %q", name, e)
		}
		if strings.Contains(e, `\`) {
			t.Fatalf("%s: entry contains backslash separator: %q", name, e)
		}
		// Reject percent-encoded traversal segments such as `%2F..%2F`
		// or `%2E%2E`. A consumer that decodes the URL before routing
		// would see `..` segments after decoding, which the link the
		// operator intended did not contain.
		lower := strings.ToLower(e)
		if strings.Contains(lower, "%2f") || strings.Contains(lower, "%2e") {
			t.Fatalf("%s: entry contains percent-encoded traversal: %q", name, e)
		}
		// Split on `/` and reject any segment that is `..`. The path
		// part of a GitHub URL is what path.Clean collapses against the
		// leading-slash wrapper; any unescaped `..` surviving here
		// means the sanitiser let an operator-controlled traversal
		// slip through.
		for _, seg := range strings.Split(e, "/") {
			if seg == ".." {
				t.Fatalf("%s: entry contains unescaped `..` segment: %q", name, e)
			}
		}
	}
}

// TestKubeGetContextCancelled verifies that a stalled apiserver call is
// cancelled promptly when the caller's context is cancelled, rather than
// blocking for the full http.Client.Timeout (15s).
func TestKubeGetContextCancelled(t *testing.T) {
	// Server that blocks on the read until the request's context is
	// cancelled, simulating a stalled apiserver.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	k := &kube{
		base: srv.URL,
		hc:   &http.Client{Timeout: 15 * time.Second},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		var out nodeList
		done <- k.get(ctx, "/api/v1/nodes", &out)
	}()

	// Give the request a moment to reach the server, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from cancelled context, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("get did not return promptly after context cancellation")
	}
}

// TestFetchPodLogsContextCancelled verifies that fetchPodLogs also honours
// context cancellation.
func TestFetchPodLogsContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	k := &kube{
		base: srv.URL,
		hc:   &http.Client{Timeout: 15 * time.Second},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan map[string]string, 1)
	go func() {
		got, _ := k.fetchPodLogs(ctx, []podLogSpec{{Namespace: "ns", Name: "pod"}}, DefaultPodLogConcurrency)
		done <- got
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case got := <-done:
		if len(got) != 0 {
			t.Errorf("expected empty map after cancellation, got %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fetchPodLogs did not return promptly after context cancellation")
	}
}

// Regression for #146: fetchPodLogs used to derive its per-pod concurrency
// from a field on the shared *kube that Enrich rewrote on every call
// (k.logConcurrency = normalizePodLogConcurrency(cfg.PodLogConcurrency)).
// Under the SIGTERM shutdown path runFlushLoop's canceled process and
// drainBuffer's new process both reach Enrich on the same *kube; the
// goroutines spawned by an in-flight fetchPodLogs read k.logConcurrency
// while the other caller's goroutine writes it, racing. Concurrency is
// now passed in by value so *kube carries no writeable per-call state:
// driving fetchPodLogs from many goroutines on a single *kube must
// never produce a -race report, regardless of what concurrency value
// each caller passes.
func TestFetchPodLogsConcurrentCallersDoNotRace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/log") {
			http.NotFound(w, r)
			return
		}
		// Hold the read open long enough that every caller has launched
		// its goroutines and is reading the same *kube simultaneously;
		// any write to kube state from a caller would race with the
		// reads other callers' goroutines are doing here.
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte("ok\n"))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, token: "tok", hc: http.DefaultClient}

	// Many concurrent callers, each with a different per-call
	// concurrency. The buggy code stored the value on *kube, so all
	// callers would race on the same field; the fix passes it on the
	// stack so there is nothing on *kube to race on.
	const callers = 8
	pods := []podLogSpec{
		{Namespace: "ns", Name: "p1"},
		{Namespace: "ns", Name: "p2"},
		{Namespace: "ns", Name: "p3"},
		{Namespace: "ns", Name: "p4"},
		{Namespace: "ns", Name: "p5"},
		{Namespace: "ns", Name: "p6"},
		{Namespace: "ns", Name: "p7"},
		{Namespace: "ns", Name: "p8"},
	}
	done := make(chan struct{}, callers)
	for i := 0; i < callers; i++ {
		concurrency := i%DefaultPodLogConcurrency + 1
		go func(c int) {
			defer func() { done <- struct{}{} }()
			got, _ := k.fetchPodLogs(context.Background(), pods, c)
			if len(got) != len(pods) {
				t.Errorf("caller concurrency=%d: expected %d logs, got %d", c, len(pods), len(got))
			}
		}(concurrency)
	}
	deadline := time.After(5 * time.Second)
	for i := 0; i < callers; i++ {
		select {
		case <-done:
		case <-deadline:
			t.Fatalf("fetchPodLogs did not return from caller %d within deadline", i)
		}
	}
}

// TestEnrichConcurrentCallersDoNotRace exercises the same shared *kube under
// concurrent Enrich callers — the SIGTERM shape that the original buggy
// pattern (k.logConcurrency = ... per call) was unsafe in. The previous
// fetchPodLogs implementation read k.logConcurrency from goroutines spawned
// inside Enrich while a concurrent Enrich wrote it, racing. With concurrency
// passed in by value there is no longer a writeable field on *kube to race
// on, so two concurrent Enrich calls (the runFlushLoop process being
// canceled and drainBuffer starting on the same *kube at shutdown) must run
// cleanly under -race.
//
// The mock apiserver returns an empty list for every known list endpoint and
// 404s anything else: a future Enrich endpoint that typos its path will trip
// the 404 instead of being silently parsed as a `{"items":[]}` body, which
// would mask the regression the test is meant to catch.
func TestEnrichConcurrentCallersDoNotRace(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/log"):
			// Hold the per-pod log read open so fetchPodLogs goroutines
			// remain in flight while a concurrent Enrich on the same
			// *kube is rewriting per-call state. Any writeable per-call
			// field on *kube would race with these reads.
			time.Sleep(100 * time.Millisecond)
			_, _ = w.Write([]byte("ok\n"))
		case strings.HasSuffix(r.URL.Path, "/pods") ||
			strings.HasSuffix(r.URL.Path, "/nodes") ||
			strings.HasSuffix(r.URL.Path, "/events") ||
			strings.Contains(r.URL.Path, "/helmreleases") ||
			strings.Contains(r.URL.Path, "/kustomizations"):
			// List endpoints Enrich calls return an empty list so the
			// parsers see a valid body.
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			// Anything Enrich does not expect — a typo'd path, a new
			// endpoint added without a handler — 404s rather than
			// silently returning a list body that another parser could
			// try to swallow.
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	k := &kube{base: srv.URL, token: "tok", hc: srv.Client(), cluster: "main"}

	mkGroup := func() Group {
		return Group{Key: "k/A", Cluster: "main", Alerts: []Alert{
			{Labels: map[string]string{"alertname": "A", "namespace": "llm", "pod": "p1"}},
		}}
	}

	const callers = 4
	done := make(chan struct{}, callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_ = k.Enrich(context.Background(), mkGroup(), time.Minute, &Config{PodLogConcurrency: 4}, nil)
		}()
	}
	deadline := time.After(10 * time.Second)
	for i := 0; i < callers; i++ {
		select {
		case <-done:
		case <-deadline:
			t.Fatalf("Enrich did not return from caller %d within deadline", i)
		}
	}
}

// fluxItem is one Flux object in a test apiserver. kind routes it to the
// helmreleases or kustomizations endpoint; status is the Ready condition's
// status value.
func fluxItem(t *testing.T, ns, name, kind, rev, transition, status string) map[string]any {
	t.Helper()
	return map[string]any{
		"kind":     kind,
		"metadata": map[string]any{"name": name, "namespace": ns},
		"status": map[string]any{
			"lastAppliedRevision": rev,
			"conditions": []map[string]any{{
				"type":               "Ready",
				"status":             status,
				"reason":             "Succeeded",
				"lastTransitionTime": transition,
			}},
		},
	}
}

// fluxServer builds a test apiserver that serves one Flux list for each of
// the helmreleases and kustomizations endpoints, routing each item to the
// endpoint named by its "kind" (as the real apiserver would).
func fluxServer(t *testing.T, items ...map[string]any) *httptest.Server {
	t.Helper()
	helm, kust := []map[string]any{}, []map[string]any{}
	for _, it := range items {
		if it["kind"] == "helmreleases" {
			helm = append(helm, it)
		} else {
			kust = append(kust, it)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		items := kust
		if strings.Contains(r.URL.Path, "helmreleases") {
			items = helm
		} else if !strings.Contains(r.URL.Path, "kustomizations") {
			http.NotFound(w, r)
			return
		}
		payload, _ := json.Marshal(map[string]any{"items": items})
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A healthy (Ready=True) Flux transition inside the window must be surfaced
// with neutral wording - "reconciled at revision ..." - never as a deploy,
// change or trigger. A new repo SHA does not prove the workload changed.
func TestFluxActivityHealthyReconcileIsNeutral(t *testing.T) {
	rev := "main@0982756e1a2b3c4d5e6f"
	srv := fluxServer(t,
		fluxItem(t, "llm", "kustomization-llm", "kustomizations", rev, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), "True"),
	)
	k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
	got := k.fluxActivity(context.Background(), "llm", time.Now().Add(-time.Hour))
	if len(got) != 1 {
		t.Fatalf("expected one healthy-reconcile line, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "reconciled at revision") {
		t.Errorf("healthy reconcile should be neutrally worded, got %q", got[0])
	}
	for _, word := range []string{"deploy", "change", "trigger"} {
		if strings.Contains(strings.ToLower(got[0]), word) {
			t.Errorf("healthy reconcile must not claim a %q, got %q", word, got[0])
		}
	}
}

// A healthy reconcile that happened outside the window must not be surfaced
// at all, even when the alert names a namespace.
func TestFluxActivityHealthyReconcileOutsideWindowIsDropped(t *testing.T) {
	rev := "main@0982756e1a2b3c4d5e6f"
	old := time.Now().Add(-10 * time.Hour).UTC().Format(time.RFC3339)
	srv := fluxServer(t, fluxItem(t, "llm", "kustomization-llm", "kustomizations", rev, old, "True"))
	k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
	got := k.fluxActivity(context.Background(), "llm", time.Now().Add(-time.Hour))
	if len(got) != 0 {
		t.Fatalf("a healthy reconcile outside the window must not surface, got %v", got)
	}
}

// A NotReady Flux resource is strong primary evidence: the reason and the
// revision must be kept verbatim, and the failure must survive even in the
// cluster-wide (ambient) scope.
func TestFluxActivityNotReadyIsFailureSignal(t *testing.T) {
	rev := "main@0982756e1a2b3c4d5e6f"
	now := time.Now().UTC().Format(time.RFC3339)
	srv := fluxServer(t, fluxItem(t, "llm", "kustomization-llm", "kustomizations", rev, now, "False"))
	k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
	got := k.fluxActivity(context.Background(), "llm", time.Now().Add(-time.Hour))
	if len(got) != 1 {
		t.Fatalf("expected one NotReady line, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "NOT READY: Succeeded") {
		t.Errorf("NotReady must keep its reason, got %q", got[0])
	}
	if !strings.Contains(got[0], "rev="+shortRev(rev)) {
		t.Errorf("NotReady must keep its revision, got %q", got[0])
	}

	// NotReady must also survive in the cluster-wide (ambient) scope: a
	// healthy sync is noise there, a failure is not.
	srv2 := fluxServer(t,
		fluxItem(t, "llm", "kustomization-llm", "kustomizations", rev, now, "False"),
		fluxItem(t, "llm", "kustomization-healthy", "kustomizations", "main@11112222333344445555", now, "True"),
	)
	k2 := &kube{base: srv2.URL, token: "tok", hc: srv2.Client()}
	ambient := k2.fluxActivity(context.Background(), "", time.Now().Add(-time.Hour))
	if len(ambient) != 1 {
		t.Fatalf("cluster-wide scope must keep only the NotReady line, got %v", ambient)
	}
	if !strings.Contains(ambient[0], "NOT READY") {
		t.Errorf("cluster-wide scope must keep the failure, got %q", ambient[0])
	}
}

// A healthy reconcile at a new revision must not be labelled a "change": the
// Enrichment field carrying these findings must not use change-encoding names
// in its rendered form either.
func TestEnrichmentFluxActivityNotChanges(t *testing.T) {
	rev := "main@0982756e1a2b3c4d5e6f"
	srv := fluxServer(t, fluxItem(t, "llm", "kustomization-llm", "kustomizations", rev, time.Now().UTC().Format(time.RFC3339), "True"))
	k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
	g := Group{
		Key:        "single/A",
		Namespaces: []string{"llm"},
		Alerts:     []Alert{{Labels: map[string]string{"alertname": "A", "namespace": "llm"}}},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, nil)
	if len(en.FluxActivity) == 0 {
		t.Fatalf("expected a FluxActivity entry, got %+v", en)
	}
	joined := strings.ToLower(strings.Join(en.FluxActivity, " "))
	for _, word := range []string{"deploy", "change", "trigger"} {
		if strings.Contains(joined, word) {
			t.Errorf("FluxActivity must not claim a %q, got %q", word, joined)
		}
	}
}

// jobAPIHarness is an httptest server that stands in for the apiserver
// endpoints Enrich touches: node health, the per-namespace pod list, warning
// events, Flux state, and the batch/v1 Job read. jobs is keyed by job name; a
// spec with missing=true makes the Job read 404. The pods list is served
// verbatim for any namespace.
func jobAPIHarness(t *testing.T, podsJSON string, jobs map[string]jobSpec) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/nodes"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.HasSuffix(path, "/pods") || strings.Contains(path, "/pods/"):
			// The per-namespace pod list and the (fetched) pod log both land
			// here; the list is the one that ends in "/pods".
			if strings.HasSuffix(path, "/pods") {
				_, _ = io.WriteString(w, podsJSON)
			} else {
				// previous=true log tail; serve an empty body so no content
				// is attached to the test's assertions.
			}
		case strings.Contains(path, "/events"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.Contains(path, "/helmreleases") || strings.Contains(path, "/kustomizations"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.Contains(path, "/jobs/"):
			name := path[strings.LastIndex(path, "/")+1:]
			if j, ok := jobs[name]; ok {
				if j.missing {
					http.NotFound(w, r)
					return
				}
				_, _ = io.WriteString(w, j.json)
				return
			}
			http.NotFound(w, r)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
}

type jobSpec struct {
	missing bool
	json    string
}

// TestEnrichJobFailedResolvesOwnedPod is the core case: a KubeJobFailed alert
// names a job via job_name (and its own namespace) but carries no pod label.
// The job's one owned pod failed, and there is an unrelated healthy pod in the
// same namespace. Enrich must resolve the job, promote the owned failed pod
// into the direct-target set (so it is reported), and record the job in
// Enrichment.InspectedJobs / Scope so the narrative can say the failed job was
// inspected rather than merely the namespace.
func TestEnrichJobFailedResolvesOwnedPod(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"backup-0","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"backup","uid":"job-uid-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}},
			{"metadata":{"name":"unrelated","namespace":"ns1",
				"ownerReferences":[{"kind":"ReplicaSet","name":"svc-0","uid":"rs-1"}]},
				"status":{"phase":"Running",
					"containerStatuses":[{"name":"c","ready":true,"restartCount":0,
						"state":{"running":{"reason":""}}}]}}
		]}`
	jobs := map[string]jobSpec{
		"backup": {json: `{"metadata":{"name":"backup","namespace":"ns1","uid":"job-uid-1"},
			"spec":{"template":{"metadata":{"labels":{"job-name":"backup"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	// The job is represented in enrichment scope.
	if len(en.InspectedJobs) != 1 || en.InspectedJobs[0] != "ns1/backup" {
		t.Fatalf("InspectedJobs = %v, want [ns1/backup]", en.InspectedJobs)
	}
	if !strings.Contains(en.Scope, "jobs ns1/backup were inspected") {
		t.Errorf("scope %q does not record that the job was inspected", en.Scope)
	}
	// The owned failed pod is a direct target and is reported.
	if !podInList(t, en.UnhealthyPods, "ns1/backup-0") {
		t.Fatalf("owned failed pod ns1/backup-0 not in UnhealthyPods: %v", en.UnhealthyPods)
	}
	// The unrelated healthy pod is not reported.
	if podInList(t, en.UnhealthyPods, "ns1/unrelated") {
		t.Errorf("unrelated healthy pod should not be unhealthy: %v", en.UnhealthyPods)
	}
}

// TestEnrichJobFailedMultipleOwnedPods covers a job that created more than one
// pod (retries / parallelism): every owned failed pod is promoted, not just the
// first one the listing happens to return.
func TestEnrichJobFailedMultipleOwnedPods(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"backup-0","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"backup","uid":"job-uid-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}},
			{"metadata":{"name":"backup-1","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"backup","uid":"job-uid-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":3,
						"state":{"error":{"reason":"CrashLoopBackOff"}}}]}}
		]}`
	jobs := map[string]jobSpec{
		"backup": {json: `{"metadata":{"name":"backup","namespace":"ns1","uid":"job-uid-1"},
			"spec":{"template":{"metadata":{"labels":{"job-name":"backup"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	if !podInList(t, en.UnhealthyPods, "ns1/backup-0") {
		t.Errorf("owned pod ns1/backup-0 missing: %v", en.UnhealthyPods)
	}
	if !podInList(t, en.UnhealthyPods, "ns1/backup-1") {
		t.Errorf("owned pod ns1/backup-1 missing: %v", en.UnhealthyPods)
	}
}

// TestEnrichJobFailedUnrelatedPod verifies that an unrelated pod in the same
// namespace (owned by something else) is not confused with the job's pod: the
// job-owned pod is promoted to the front of the unhealthy list ahead of a
// higher-scoring unrelated pod, so it survives truncation.
func TestEnrichJobFailedUnrelatedPod(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"backup-0","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"backup","uid":"job-uid-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}},
			{"metadata":{"name":"noisy","namespace":"ns1",
				"ownerReferences":[{"kind":"DaemonSet","name":"ds-0","uid":"ds-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":5,
						"state":{"error":{"reason":"OOMKilled"}}}]}}
		]}`
	jobs := map[string]jobSpec{
		"backup": {json: `{"metadata":{"name":"backup","namespace":"ns1","uid":"job-uid-1"},
			"spec":{"template":{"metadata":{"labels":{"job-name":"backup"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	iOwned, iNoisy := -1, -1
	for i, p := range en.UnhealthyPods {
		if strings.Contains(p, "ns1/backup-0") {
			iOwned = i
		}
		if strings.Contains(p, "ns1/noisy") {
			iNoisy = i
		}
	}
	if iOwned < 0 || iNoisy < 0 {
		t.Fatalf("expected both owned and unrelated pods, got %v", en.UnhealthyPods)
	}
	if iOwned > iNoisy {
		t.Errorf("job-owned pod must come before the unrelated pod (iOwned=%d, iNoisy=%d): %v", iOwned, iNoisy, en.UnhealthyPods)
	}
}

// TestEnrichSubjectPodProvenanceExcludesUnrelatedNoise is the issue #136
// review regression. A resolved subject pod (here the Job-owned backup-0) and
// an unrelated failing pod can both be in the namespace scan. Only the
// subject's state, diagnostics and termination message may be classified as
// direct evidence; the unrelated pod must stay in the context tier, or the
// renderer promotes namespace noise into a tier the prompt says was read from
// the alert's own object.
func TestEnrichSubjectPodProvenanceExcludesUnrelatedNoise(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"backup-0","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"backup","uid":"job-uid-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"terminated":{"exitCode":1,"reason":"Error","message":"owned failure"}}}]}},
			{"metadata":{"name":"noisy","namespace":"ns1",
				"ownerReferences":[{"kind":"DaemonSet","name":"ds-0","uid":"ds-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"terminated":{"exitCode":1,"reason":"Error","message":"noise failure"}}}]}}
		]}`
	jobs := map[string]jobSpec{
		"backup": {json: `{"metadata":{"name":"backup","namespace":"ns1","uid":"job-uid-1"},
			"spec":{"template":{"metadata":{"labels":{"job-name":"backup"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	if !podInList(t, en.SubjectPods, "ns1/backup-0") {
		t.Errorf("job-owned pod missing from SubjectPods: %v", en.SubjectPods)
	}
	if podInList(t, en.SubjectPods, "ns1/noisy") {
		t.Errorf("unrelated pod promoted to SubjectPods: %v", en.SubjectPods)
	}
	if !podInList(t, en.ContextPods, "ns1/noisy") {
		t.Errorf("unrelated pod missing from ContextPods: %v", en.ContextPods)
	}
	if podInList(t, en.ContextPods, "ns1/backup-0") {
		t.Errorf("subject pod leaked into ContextPods: %v", en.ContextPods)
	}
	if !podInList(t, en.SubjectContainerDiagnostics, "ns1/backup-0") || podInList(t, en.SubjectContainerDiagnostics, "ns1/noisy") {
		t.Errorf("SubjectContainerDiagnostics = %v, want only ns1/backup-0", en.SubjectContainerDiagnostics)
	}
	if !podInList(t, en.ContextContainerDiagnostics, "ns1/noisy") || podInList(t, en.ContextContainerDiagnostics, "ns1/backup-0") {
		t.Errorf("ContextContainerDiagnostics = %v, want only ns1/noisy", en.ContextContainerDiagnostics)
	}
	if !podInList(t, en.SubjectContainerTerminationMessages, "owned failure") || podInList(t, en.SubjectContainerTerminationMessages, "noise failure") {
		t.Errorf("SubjectContainerTerminationMessages = %v, want only the subject message", en.SubjectContainerTerminationMessages)
	}
	if !podInList(t, en.ContextContainerTerminationMessages, "noise failure") || podInList(t, en.ContextContainerTerminationMessages, "owned failure") {
		t.Errorf("ContextContainerTerminationMessages = %v, want only the unrelated message", en.ContextContainerTerminationMessages)
	}

	got := renderEvidence(Report{Group: g, Enrichment: en})
	directIdx := strings.Index(got, "DIRECT SUBJECT EVIDENCE")
	contextIdx := strings.Index(got, "CONTEXT / BACKGROUND")
	if directIdx < 0 || contextIdx < 0 || directIdx > contextIdx {
		t.Fatalf("missing or misordered tier headings:\n%s", got)
	}
	if i := strings.Index(got, "owned failure"); i < directIdx || i > contextIdx {
		t.Errorf("subject termination message at %d must sit in DIRECT [%d, %d]:\n%s", i, directIdx, contextIdx, got)
	}
	ni := strings.Index(got, "noise failure")
	if ni < 0 {
		t.Fatalf("unrelated message not rendered at all:\n%s", got)
	}
	if ni < contextIdx {
		t.Errorf("unrelated termination message at %d must not appear in DIRECT (context starts at %d):\n%s", ni, contextIdx, got)
	}
	if i := strings.Index(got, "ns1/noisy"); i >= 0 && i < contextIdx {
		t.Errorf("unrelated pod at %d appeared before the context tier (%d):\n%s", i, contextIdx, got)
	}
}

// TestEnrichAbsentSubjectPodNotObserved covers the other half of the review:
// an alert names a pod that is absent from the namespace listing. Nothing was
// inspected, so SubjectPodObserved must stay false and the renderer must say
// so rather than report the missing pod as healthy.
func TestEnrichAbsentSubjectPodNotObserved(t *testing.T) {
	pods := `{"items":[
		{"metadata":{"name":"other","namespace":"ns1"},
			"status":{"phase":"Failed",
				"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
					"state":{"error":{"reason":"Error"}}}]}}
	]}`
	srv := jobAPIHarness(t, pods, nil)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubePodNotReady", "namespace": "ns1", "pod": "ghost",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	if en.SubjectPodObserved {
		t.Errorf("absent subject pod must not be recorded as observed")
	}
	if len(en.SubjectPods) != 0 {
		t.Errorf("absent subject must yield no subject pods, got %v", en.SubjectPods)
	}
	if !podInList(t, en.ContextPods, "ns1/other") {
		t.Errorf("unrelated namespace pod should be context, got %v", en.ContextPods)
	}
	got := renderEvidence(Report{Group: g, Enrichment: en})
	if !strings.Contains(got, "No subject pod was observed for this alert") {
		t.Errorf("renderer should report the missing subject, not a health negative:\n%s", got)
	}
}

// TestEnrichJobFailedMissingJob covers a job that is gone (404): enrichment
// must degrade gracefully — no job in InspectedJobs, no job in the scope
// string — and must still ship the namespace listing it gathered.
func TestEnrichJobFailedMissingJob(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"stray","namespace":"ns1",
				"ownerReferences":[{"kind":"ReplicaSet","name":"svc-0","uid":"rs-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}}
		]}`
	jobs := map[string]jobSpec{"backup": {missing: true}}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	if len(en.InspectedJobs) != 0 {
		t.Fatalf("missing job should not be recorded as inspected, got %v", en.InspectedJobs)
	}
	if strings.Contains(en.Scope, "jobs ") {
		t.Errorf("scope should not name a job when the job is missing: %q", en.Scope)
	}
	// The namespace listing still runs, so a genuinely unhealthy pod is still
	// reported even though the job could not be resolved.
	if !podInList(t, en.UnhealthyPods, "ns1/stray") {
		t.Fatalf("expected the namespace listing to still surface the unhealthy pod, got %v", en.UnhealthyPods)
	}
}

// TestEnrichPodLabelUnchanged is a regression guard: an alert that names its
// subject with a `pod` label (no `job_name`) must behave exactly as before —
// no job is fetched, nothing is recorded in InspectedJobs — and the pod it
// names is a direct target.
func TestEnrichPodLabelUnchanged(t *testing.T) {
	var jobHits int
	pods := `{
		"items":[
			{"metadata":{"name":"web-0","namespace":"ns1",
				"ownerReferences":[{"kind":"ReplicaSet","name":"web-0","uid":"rs-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}}
		]}`
	counting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case strings.Contains(path, "/jobs/"):
			jobHits++
			http.NotFound(w, r)
		case strings.HasSuffix(path, "/nodes"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.HasSuffix(path, "/pods"):
			_, _ = io.WriteString(w, pods)
		case strings.Contains(path, "/events") || strings.Contains(path, "/helmreleases") || strings.Contains(path, "/kustomizations"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	defer counting.Close()

	k := &kube{base: counting.URL, hc: counting.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubePodNotReady", "namespace": "ns1", "pod": "web-0",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	if jobHits != 0 {
		t.Fatalf("a pod-labelled alert with no job_name must not fetch any job, got %d job hit(s)", jobHits)
	}
	if len(en.InspectedJobs) != 0 {
		t.Fatalf("no job was named, so InspectedJobs must be empty, got %v", en.InspectedJobs)
	}
	// The pod the alert names is still a direct target and is reported.
	if !podInList(t, en.UnhealthyPods, "ns1/web-0") {
		t.Fatalf("pod-labelled alert's own pod should be a direct target, got %v", en.UnhealthyPods)
	}
}

// podInList reports whether any entry of got names the given "ns/name" pod
// (the enriched list is a slice of "ns/name <phase> ..." strings).
func podInList(t *testing.T, got []string, key string) bool {
	t.Helper()
	for _, s := range got {
		if strings.Contains(s, key) {
			return true
		}
	}
	return false
}

// TestEnrichJobFailedMultipleJobs pins the scope statement for a group whose
// alerts name more than one job: the resolved jobs are recorded in
// InspectedJobs in a stable (sorted) order and the scope names all of them, so
// "jobs ns1/b, ns1/a were inspected" is the same string on every run.
func TestEnrichJobFailedMultipleJobs(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"a-0","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"a","uid":"ua"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}},
			{"metadata":{"name":"b-0","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"b","uid":"ub"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}}
		]}`
	jobs := map[string]jobSpec{
		"a": {json: `{"metadata":{"name":"a","namespace":"ns1","uid":"ua"},"spec":{"template":{"metadata":{"labels":{"job-name":"a"}}}}}`},
		"b": {json: `{"metadata":{"name":"b","namespace":"ns1","uid":"ub"},"spec":{"template":{"metadata":{"labels":{"job-name":"b"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{
			{Labels: map[string]string{"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "a"}},
			{Labels: map[string]string{"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "b"}},
		},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	if len(en.InspectedJobs) != 2 || en.InspectedJobs[0] != "ns1/a" || en.InspectedJobs[1] != "ns1/b" {
		t.Fatalf("InspectedJobs not sorted, got %v", en.InspectedJobs)
	}
	if !strings.Contains(en.Scope, "jobs ns1/a, ns1/b were inspected") {
		t.Errorf("scope should name both jobs in sorted order: %q", en.Scope)
	}
	// Both jobs' owned failed pods are promoted into the direct-target set.
	if !podInList(t, en.UnhealthyPods, "ns1/a-0") || !podInList(t, en.UnhealthyPods, "ns1/b-0") {
		t.Fatalf("both owned failed pods should be reported, got %v", en.UnhealthyPods)
	}
}

// TestEnrichJobFailedMultipleJobsOwnership keeps ownership evidence complete
// when a correlated group resolves several Jobs. Each pod must be chained to
// its own Job and controller, never another resolved Job.
func TestEnrichJobFailedMultipleJobsOwnership(t *testing.T) {
	pods := `{"items":[
		{"metadata":{"name":"a-0","namespace":"ns1","ownerReferences":[{"kind":"Job","name":"a","uid":"ua"}]},"status":{"phase":"Failed","containerStatuses":[{"name":"c","ready":false,"state":{"error":{"reason":"Error"}}}]}},
		{"metadata":{"name":"b-0","namespace":"ns1","ownerReferences":[{"kind":"Job","name":"b","uid":"ub"}]},"status":{"phase":"Failed","containerStatuses":[{"name":"c","ready":false,"state":{"error":{"reason":"Error"}}}]}}
	]}`
	jobs := map[string]jobSpec{
		"a": {json: `{"metadata":{"name":"a","namespace":"ns1","uid":"ua","ownerReferences":[{"kind":"Backup","name":"nightly-a","controller":true}]},"spec":{"template":{"metadata":{"labels":{"job-name":"a"}}}}}`},
		"b": {json: `{"metadata":{"name":"b","namespace":"ns1","uid":"ub","ownerReferences":[{"kind":"Migration","name":"nightly-b","controller":true}]},"spec":{"template":{"metadata":{"labels":{"job-name":"b"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{Namespaces: []string{"ns1"}, Alerts: []Alert{
		{Labels: map[string]string{"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "a"}},
		{Labels: map[string]string{"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "b"}},
	}}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	for _, want := range []string{
		"Job/ns1/a -> Backup/nightly-a",
		"Pod/ns1/a-0 -> Job/ns1/a -> Backup/nightly-a",
		"Job/ns1/b -> Migration/nightly-b",
		"Pod/ns1/b-0 -> Job/ns1/b -> Migration/nightly-b",
	} {
		found := false
		for _, got := range en.Ownership {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Ownership missing %q: %v", want, en.Ownership)
		}
	}
	for _, got := range en.Ownership {
		if strings.Contains(got, "Pod/ns1/a-0 -> Job/ns1/b") || strings.Contains(got, "Pod/ns1/b-0 -> Job/ns1/a") {
			t.Errorf("pod was cross-associated with another job: %q", got)
		}
	}
}

// TestJobOwnedByFallback covers the ownership rule: a pod with a Job owner
// reference is attributed by that reference (name + uid), and the
// job-name=<name> label fallback is used only when no Job owner reference is
// present at all. A pod owned by a different job must never be claimed.
func TestJobOwnedByFallback(t *testing.T) {
	job := jobRef{Namespace: "ns1", Name: "backup", UID: "job-uid-1", ControllerKey: "job-name", LabelValue: "backup"}

	cases := []struct {
		name string
		pod  podOwner
		want bool
	}{
		{"owned by uid and name", podOwner{OwnerReferences: []ownerRef{{Kind: "Job", Name: "backup", UID: "job-uid-1"}}}, true},
		{"owned by name, uid missing", podOwner{OwnerReferences: []ownerRef{{Kind: "Job", Name: "backup"}}}, true},
		{"owned by a different job", podOwner{OwnerReferences: []ownerRef{{Kind: "Job", Name: "other", UID: "x"}}, Labels: map[string]string{"job-name": "backup"}}, false},
		{"no owner ref, label fallback matches", podOwner{Labels: map[string]string{"job-name": "backup"}}, true},
		{"no owner ref, label fallback misses", podOwner{Labels: map[string]string{"job-name": "other"}}, false},
	}
	for _, tc := range cases {
		if got := jobOwnedBy(job, tc.pod); got != tc.want {
			t.Errorf("jobOwnedBy(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestEnrichJobFailedControllerOwnedJob is the motivating incident of #131:
// the failed Job is a generated backup task owned by a custom-resource
// controller even though its name is derived from the application. The
// enrichment must carry the ownership chain so the model can tell the
// generated job apart from the application, and must not infer the
// relationship from the job's name.
func TestEnrichJobFailedControllerOwnedJob(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"backup-0","namespace":"ns1","uid":"pod-uid-1",
				"labels":{"job-name":"backup","controller":"backup"},
				"ownerReferences":[{"kind":"Job","apiVersion":"batch/v1","name":"backup","uid":"job-uid-1","controller":true}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}}
		]}`
	jobs := map[string]jobSpec{
		"backup": {json: `{
			"metadata":{"name":"backup","namespace":"ns1","uid":"job-uid-1",
				"labels":{"app.kubernetes.io/managed-by":"velero","app.kubernetes.io/component":"backup"},
				"ownerReferences":[{"kind":"Backup","apiVersion":"velero.io/v1","name":"nightly","uid":"cr-uid-1","controller":true}]},
			"spec":{"template":{"metadata":{"labels":{"job-name":"backup"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	if len(en.Ownership) != 2 {
		t.Fatalf("Ownership = %v, want 2 entries (job and its pod)", en.Ownership)
	}
	if !strings.Contains(en.Ownership[0], "Job/ns1/backup -> Backup/nightly") {
		t.Errorf("job chain %q must continue to its controller owner", en.Ownership[0])
	}
	if !strings.Contains(en.Ownership[0], "app.kubernetes.io/managed-by=velero") {
		t.Errorf("job chain %q must carry the curated identity label", en.Ownership[0])
	}
	if !strings.Contains(en.Ownership[1], "Pod/ns1/backup-0") ||
		!strings.Contains(en.Ownership[1], "-> Job/ns1/backup -> Backup/nightly") {
		t.Errorf("pod chain %q must read end to end as pod -> job -> controller", en.Ownership[1])
	}
}

// TestEnrichJobFailedOwnerlessJob: a job with no ownerReferences must not
// acquire a fabricated parent from its name, and enrichment must not fail.
func TestEnrichJobFailedOwnerlessJob(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"backup-0","namespace":"ns1","uid":"pod-uid-1",
				"labels":{"job-name":"backup"},
				"ownerReferences":[{"kind":"Job","apiVersion":"batch/v1","name":"backup","uid":"job-uid-1","controller":true}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}}
		]}`
	jobs := map[string]jobSpec{
		"backup": {json: `{
			"metadata":{"name":"backup","namespace":"ns1","uid":"job-uid-1",
				"labels":{"app.kubernetes.io/name":"myapp"}},
			"spec":{"template":{"metadata":{"labels":{"job-name":"backup"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	if len(en.Ownership) != 2 {
		t.Fatalf("Ownership = %v, want 2 entries", en.Ownership)
	}
	// No controller: the job entry is just the name plus its identity label.
	if en.Ownership[0] != "Job/ns1/backup [app.kubernetes.io/name=myapp]" {
		t.Errorf("ownerless job chain = %q, want no parent hop", en.Ownership[0])
	}
	// No controller: the chain stops at the job; exactly one hop.
	if en.Ownership[1] != "Pod/ns1/backup-0 -> Job/ns1/backup" {
		t.Errorf("pod chain of an ownerless job = %q, want a single hop", en.Ownership[1])
	}
}

// TestEnrichJobFailedPodOwnedByResolvedJob: a pod the listing shows is owned
// by the resolved job (uid match) gets a chain entry, and a pod owned by
// something else does not.
func TestEnrichJobFailedPodOwnedByResolvedJob(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"backup-0","namespace":"ns1","uid":"pod-uid-1",
				"labels":{"job-name":"backup"},
				"ownerReferences":[{"kind":"Job","apiVersion":"batch/v1","name":"backup","uid":"job-uid-1","controller":true}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}}
			,{"metadata":{"name":"other-0","namespace":"ns1","uid":"pod-uid-2",
				"labels":{},
				"ownerReferences":[{"kind":"ReplicaSet","apiVersion":"apps/v1","name":"other-0","uid":"rs-1","controller":true}]},
				"status":{"phase":"Running",
					"containerStatuses":[{"name":"c","ready":true,"restartCount":0,
						"state":{"running":{"reason":""}}}]}}
		]}`
	jobs := map[string]jobSpec{
		"backup": {json: `{
			"metadata":{"name":"backup","namespace":"ns1","uid":"job-uid-1",
				"ownerReferences":[{"kind":"Backup","apiVersion":"velero.io/v1","name":"nightly","uid":"cr-uid-1","controller":true}]},
			"spec":{"template":{"metadata":{"labels":{"job-name":"backup"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	for _, s := range en.Ownership {
		if strings.Contains(s, "Pod/ns1/other-0") {
			t.Errorf("pod owned by a different controller must not get a chain: %v", en.Ownership)
		}
	}
	found := false
	for _, s := range en.Ownership {
		if strings.Contains(s, "Pod/ns1/backup-0 -> Job/ns1/backup") {
			found = true
		}
	}
	if !found {
		t.Errorf("pod owned by the resolved job is missing its chain: %v", en.Ownership)
	}
}

// TestControllerOwnerRefPrefer checks the controller-preference rule when an
// object carries both a controller and a non-controller reference: the
// non-controller one is a secondary association and must not be chained.
func TestControllerOwnerRefPrefer(t *testing.T) {
	tt := true
	ff := false
	cases := []struct {
		name      string
		refs      []ownerRef
		want      ownerRef
		wantFound bool
	}{
		{"empty", nil, ownerRef{}, false},
		{"only empty", []ownerRef{{}}, ownerRef{}, false},
		{
			"mixed: the controller-flagged ref is chosen",
			[]ownerRef{
				{Kind: "Job", Name: "backup", UID: "u1", Controller: &tt},
				{Kind: "Backup", Name: "nightly", UID: "u2", Controller: &ff},
			},
			ownerRef{Kind: "Job", Name: "backup", UID: "u1", Controller: &tt},
			true,
		},
		{
			"controller second",
			[]ownerRef{
				{Kind: "Backup", Name: "nightly", UID: "u2", Controller: &ff},
				{Kind: "Job", Name: "backup", UID: "u1", Controller: &tt},
			},
			ownerRef{Kind: "Job", Name: "backup", UID: "u1", Controller: &tt},
			true,
		},
		{
			"no controller flag: first non-empty wins",
			[]ownerRef{
				{Kind: "DaemonSet", Name: "ds-0", UID: "u1"},
				{Kind: "Job", Name: "backup", UID: "u2"},
			},
			ownerRef{Kind: "DaemonSet", Name: "ds-0", UID: "u1"},
			true,
		},
	}
	for _, tc := range cases {
		got, ok := controllerOwnerRef(tc.refs)
		if ok != tc.wantFound || got != tc.want {
			t.Errorf("controllerOwnerRef(%s) = %+v, %v; want %+v, %v", tc.name, got, ok, tc.want, tc.wantFound)
		}
	}
}

// TestIdentityTagsWhitelist: only curated identity keys are surfaced, with
// their values, in a stable preference order; high-cardinality and unknown
// keys are never shown.
func TestIdentityTagsWhitelist(t *testing.T) {
	got := identityTags(
		map[string]string{
			"app.kubernetes.io/managed-by": "velero",
			"app.kubernetes.io/name":       "myapp",
			"pod-template-hash":            "abc123",
			"controller-uid":               "uid-999",
			"job-name":                     "backup",
		},
		map[string]string{
			"kustomize.toolkit.fluxcd.io/name": "myapp-kustomization",
		},
	)
	for _, want := range []string{
		"app.kubernetes.io/managed-by=velero",
		"app.kubernetes.io/name=myapp",
		"kustomize.toolkit.fluxcd.io/name=myapp-kustomization",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("identityTags missing %q in %q", want, got)
		}
	}
	for _, banned := range []string{"pod-template-hash", "controller-uid", "job-name="} {
		if strings.Contains(got, banned) {
			t.Errorf("identityTags leaked non-identity key %q in %q", banned, got)
		}
	}
	if got != "app.kubernetes.io/managed-by=velero,app.kubernetes.io/name=myapp,kustomize.toolkit.fluxcd.io/name=myapp-kustomization" {
		t.Errorf("unexpected identity order: %q", got)
	}
}

func TestEnrichScopesResolvedJobAndOwnedPodEvents(t *testing.T) {
	eventTime := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	var eventHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/nodes"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.HasSuffix(r.URL.Path, "/pods"):
			_, _ = io.WriteString(w, `{"items":[
				{"metadata":{"name":"backup-0","namespace":"ns1","labels":{"job-name":"backup"}},"status":{"phase":"Failed","containerStatuses":[{"name":"job","ready":false,"state":{"terminated":{"reason":"Error"}}}]}},
				{"metadata":{"name":"notifier-0","namespace":"ns1"},"status":{"phase":"Running","containerStatuses":[{"name":"notifier","ready":true,"state":{"running":{}}}]}}
			]}`)
		case strings.Contains(r.URL.Path, "/jobs/"):
			_, _ = io.WriteString(w, `{"metadata":{"name":"backup","namespace":"ns1","uid":"job-uid-1"},"spec":{"template":{"metadata":{"labels":{"job-name":"backup"}}}}}`)
		case strings.Contains(r.URL.Path, "/events"):
			eventHits++
			_, _ = io.WriteString(w, `{"items":[
				{"reason":"BackoffLimitExceeded","message":"job failed","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"Job","name":"backup","namespace":"ns1"}},
				{"reason":"BackoffLimitExceeded","message":"job failed","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"Job","name":"backup","namespace":"ns1"}},
				{"reason":"Failed","message":"pod failed","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"Pod","name":"backup-0","namespace":"ns1"}},
				{"reason":"FailedMount","message":"unrelated pvc","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"PersistentVolumeClaim","name":"data","namespace":"ns1"}},
				{"reason":"Failed","message":"unrelated pod","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"Pod","name":"notifier-0","namespace":"ns1"}},
				{"reason":"AlertFiring","message":"unrelated alert","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"Alert","name":"other","namespace":"ns1"}}
			]}`)
		default:
			_, _ = io.WriteString(w, `{"items":[]}`)
		}
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{
			{Labels: map[string]string{"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup"}},
			{Labels: map[string]string{"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup"}},
		},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, nil)

	if !en.EventsScoped {
		t.Fatal("resolved job should scope events")
	}
	if eventHits != 1 {
		t.Fatalf("expected one event fetch for the namespace, got %d", eventHits)
	}
	if len(en.Events) != 2 || !strings.Contains(en.Events[0], "BackoffLimitExceeded x2") || !strings.Contains(en.Events[1], "backup-0") {
		t.Fatalf("expected aggregated Job and owned Pod evidence, got %v", en.Events)
	}
	if len(en.Ambient) != 3 {
		t.Fatalf("expected unrelated PVC, Pod, and Alert events in ambient, got %v", en.Ambient)
	}
	for _, item := range en.Events {
		if strings.Contains(item, "data") || strings.Contains(item, "notifier-0") || strings.Contains(item, "other") {
			t.Errorf("unrelated event became primary evidence: %q", item)
		}
	}
}

func TestRenderScopedEventNegative(t *testing.T) {
	got := renderEvidence(Report{Enrichment: Enrichment{EventsScoped: true}})
	if !strings.Contains(got, "no warning events on the resolved subject in the window") {
		t.Fatalf("missing scoped event negative: %s", got)
	}
}

func TestEnrichNoSubjectEventsAreAmbient(t *testing.T) {
	eventTime := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/events") {
			_, _ = io.WriteString(w, `{"items":[{"reason":"FailedMount","message":"background pvc","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"PersistentVolumeClaim","name":"data","namespace":"ns1"}}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"items":[]}`)
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{Namespaces: []string{"ns1"}, Alerts: []Alert{{Labels: map[string]string{"alertname": "KubePodNotReady", "namespace": "ns1"}}}}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, nil)
	if en.EventsScoped || len(en.Events) != 0 {
		t.Fatalf("no resolved subject must not have primary events: scoped=%v events=%v", en.EventsScoped, en.Events)
	}
	if len(en.Ambient) != 1 || !strings.Contains(en.Ambient[0], "PersistentVolumeClaim") {
		t.Fatalf("namespace event should be ambient background, got %v", en.Ambient)
	}
	got := renderEvidence(Report{Group: g, Enrichment: en})
	if !strings.Contains(got, "BACKGROUND") || strings.Contains(got, "no warning events on the resolved subject in the window") {
		t.Fatalf("fallback evidence should be broad/background, got %s", got)
	}
}

// newLogsBackendForTest builds a logsBackend wired to a test server without
// touching process environment, so Enrich-level tests can exercise the
// backend-logs path directly.
func newLogsBackendForTest(t *testing.T, srv *httptest.Server) *logsBackend {
	t.Helper()
	return &logsBackend{
		url:    srv.URL,
		base:   srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
}

// TestEnrichBackendLogsNoSubjectGoesAmbient proves the Enrich-level routing:
// when the alert resolves to no concrete subject, the namespace-wide
// backend-log lookup is kept but its result is explicitly marked ambient and
// is not presented as evidence from the failing resource.
func TestEnrichBackendLogsNoSubjectGoesAmbient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/pods") || strings.Contains(r.URL.Path, "/log") || strings.Contains(r.URL.Path, "/nodes") || strings.Contains(r.URL.Path, "/events") {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/select") || strings.Contains(r.URL.Path, "/loki/") {
			q := r.URL.Query().Get("query")
			if q != `{namespace="ns1"}` {
				t.Errorf("exact namespace-only selector expected, got %q", q)
			}
			_, _ = io.WriteString(w, `{"status":"success","data":{"result":[{"stream":{"pod":"unrelated","namespace":"ns1"},"values":[["1","namespace chatter line"]]}]}}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(srv.Close)

	k := &kube{base: srv.URL, hc: srv.Client(), logs: newLogsBackendForTest(t, srv)}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{
			{Status: "firing", Labels: map[string]string{"alertname": "KubePodNotReady", "namespace": "ns1"}},
		},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	if len(en.BackendLogs) != 0 {
		t.Fatalf("namespace-wide logs must not enter primary evidence without a subject, got %v", en.BackendLogs)
	}
	// "empty" here would be false: the backend answered and its namespace-wide
	// lines are the Ambient entries below. The state must say so.
	if en.BackendState != "ambient" {
		t.Fatalf("expected state \"ambient\" (no subject resolved, namespace-wide lines returned), got %q", en.BackendState)
	}
	if en.BackendScoped {
		t.Errorf("no subject was resolved, so the backend query was not subject-scoped")
	}
	foundAmbient := false
	for _, a := range en.Ambient {
		if !strings.Contains(a, "(ambient, namespace-wide)") {
			continue
		}
		foundAmbient = true
		if !strings.Contains(a, "namespace chatter line") {
			t.Fatalf("ambient line must be the namespace-wide line, got %q", a)
		}
	}
	if !foundAmbient {
		t.Fatalf("expected one ambient-marked backend-log line, got %v", en.Ambient)
	}
}

// TestEnrichBackendLogsNoSubjectEmptyNotScoped is the issue #136 review
// regression for the ambiguous "empty" state: with no resolved subject the
// namespace-only fallback ran and returned nothing. The query was not
// subject-scoped, so the rendered evidence must not claim it looked for the
// subject's lines.
func TestEnrichBackendLogsNoSubjectEmptyNotScoped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/select") || strings.Contains(r.URL.Path, "/loki/") {
			_, _ = io.WriteString(w, `{"status":"success","data":{"result":[]}}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(srv.Close)

	k := &kube{base: srv.URL, hc: srv.Client(), logs: newLogsBackendForTest(t, srv)}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubePodNotReady", "namespace": "ns1"}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	if en.BackendState != "empty" {
		t.Fatalf("expected state \"empty\", got %q", en.BackendState)
	}
	if en.BackendScoped {
		t.Fatalf("no subject was resolved, so the query must not be marked subject-scoped")
	}
	got := renderEvidence(Report{Group: g, Enrichment: en})
	if strings.Contains(got, "for this subject") {
		t.Errorf("namespace-fallback empty state must not claim a subject inspection:\n%s", got)
	}
	if !strings.Contains(got, "returned no lines for the namespace in the window") {
		t.Errorf("expected the namespace-scoped empty wording:\n%s", got)
	}
}

// TestEnrichBackendLogsTargetPodIsPrimary proves the primary path: when the
// resolved target-pod set is non-empty, backend logs are pod-scoped, the
// namespace-wide query is not issued, and unrelated namespace log lines never
// enter the evidence.
func TestEnrichBackendLogsTargetPodIsPrimary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/pods") || strings.Contains(r.URL.Path, "/log") || strings.Contains(r.URL.Path, "/nodes") || strings.Contains(r.URL.Path, "/events") {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/select") || strings.Contains(r.URL.Path, "/loki/") {
			q := r.URL.Query().Get("query")
			if !strings.Contains(q, `pod="p1"`) {
				t.Errorf("expected only a pod-scoped query, got %q", q)
			}
			_, _ = io.WriteString(w, `{"status":"success","data":{"result":[{"stream":{"pod":"p1","namespace":"ns1"},"values":[["1","target failure line"]]}]}}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(srv.Close)

	k := &kube{base: srv.URL, hc: srv.Client(), logs: newLogsBackendForTest(t, srv)}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{
			{Status: "firing", Labels: map[string]string{"alertname": "KubePodNotReady", "namespace": "ns1", "pod": "p1"}},
		},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	if len(en.BackendLogs) != 1 || !strings.Contains(en.BackendLogs[0], "target failure line") {
		t.Fatalf("expected the target pod's line as the only primary line, got %v", en.BackendLogs)
	}
	if en.BackendState != "ok" {
		t.Fatalf("expected state \"ok\", got %q", en.BackendState)
	}
	if !en.BackendScoped {
		t.Errorf("a resolved target pod must mark the backend query subject-scoped")
	}
	for _, a := range en.Ambient {
		if strings.Contains(a, "(ambient, namespace-wide)") {
			t.Fatalf("no ambient backend logs expected when a subject is resolved, got %v", en.Ambient)
		}
	}
}

// Captured-real-alert replay for the #218 shapes: the pod-log lines recorded
// in issue #218 (observed on the cluster during the #207 review) are driven
// through the production consumer — Enrich's backend-log query with a resolved
// subject, not a direct stripSecrets call — and into the digest evidence the
// model is given. Each captured credential shape must arrive redacted, the
// prose line must survive byte-identical, and no captured credential byte may
// reach the evidence either way. The chain shapes from #221 come along
// because a credential hidden behind another one used to survive the same
// path.
func TestEnrichBackendLogsCapturedBasicAuthShapes(t *testing.T) {
	shapes := []string{
		"proxy-authorization: Basic%20Zm9vOmJhcg%3D%3D",
		"authorization=Basic%20dXNlcjpwYXNz",
		"basic%20Zm9vOmJhcg%3D%3D",
		"authorization: Negotiate=dXNlcjpwYXNz",
		"basic auth failed for basic.io keep this sentence",
		"basic dXNlcjpwYXNz%3Dbasic dXVpZDpwYXNz",
		"basic dXNlcjpwYXNz%3D.authorization dXVpZDpwYXNz",
		"basic dXNlcjpwYXNz%3abasic dXVpZDpwYXNz",
		"%3Dbasic%20dXNlcjpwYXNz",
		"0basic%20dXNlcjpwYXNz",
	}
	entries := make([]string, len(shapes))
	for i, line := range shapes {
		entries[i] = fmt.Sprintf(`{"stream":{"pod":"web-fallback-1","namespace":"default"},"values":[["1",%q]]}`, line)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/pods") || strings.Contains(r.URL.Path, "/log") ||
			strings.Contains(r.URL.Path, "/nodes") || strings.Contains(r.URL.Path, "/events") {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/select") || strings.Contains(r.URL.Path, "/loki/") {
			q := r.URL.Query().Get("query")
			if !strings.Contains(q, `pod="web-fallback-1"`) {
				t.Errorf("expected only a pod-scoped query, got %q", q)
			}
			_, _ = io.WriteString(w, `{"status":"success","data":{"result":[`+strings.Join(entries, ",")+`]}}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(srv.Close)

	k := &kube{base: srv.URL, hc: srv.Client(), logs: newLogsBackendForTest(t, srv)}
	g := Group{
		Namespaces: []string{"default"},
		Alerts: []Alert{
			{Status: "firing", Labels: map[string]string{"alertname": "KubePodNotReady", "namespace": "default", "pod": "web-fallback-1"}},
		},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	if en.BackendState != "ok" {
		t.Fatalf("expected backend state \"ok\", got %q", en.BackendState)
	}
	if !en.BackendScoped {
		t.Errorf("a resolved target pod must mark the backend query subject-scoped")
	}
	if len(en.BackendLogs) != len(shapes) {
		t.Fatalf("expected %d backend log lines, got %d: %v", len(shapes), len(en.BackendLogs), en.BackendLogs)
	}
	evidence := renderEvidence(Report{Cfg: &Config{}, Group: g, Enrichment: en})
	const prose = "basic auth failed for basic.io keep this sentence"
	leakTokens := []string{"Zm9vOmJhcg%3D%3D", "dXNlcjpwYXNz", "dXVpZDpwYXNz"}
	for _, sink := range []struct {
		where string
		lines []string
	}{
		{"BackendLogs", en.BackendLogs},
		{"rendered evidence", []string{evidence}},
	} {
		joined := strings.Join(sink.lines, "\n")
		for _, tok := range leakTokens {
			if strings.Contains(joined, tok) {
				t.Errorf("captured credential %q survived into %s", tok, sink.where)
			}
		}
		if !strings.Contains(joined, prose) {
			t.Errorf("prose line did not survive byte-identical into %s", sink.where)
		}
	}
	wantRedacted := []string{
		"proxy-authorization: [REDACTED]",
		"authorization=[REDACTED]",
		"basic%20[REDACTED]",
		"authorization: Negotiate=[REDACTED]",
	}
	for _, want := range wantRedacted {
		if !strings.Contains(strings.Join(en.BackendLogs, "\n"), want) {
			t.Errorf("backend logs missing redacted form %q, got %v", want, en.BackendLogs)
		}
		if !strings.Contains(evidence, want) {
			t.Errorf("rendered evidence missing redacted form %q", want)
		}
	}
}

// Issue #128: a failed one-shot Job container (terminated once, never
// restarted) must surface as a ContainerDiagnostic and have its log fetched
// as the CURRENT stream, not previous. The previous-stream request would 404
// because no previous instance ever existed.
func TestEnrich_oneShotTerminatedContainerFetchesCurrentLog(t *testing.T) {
	logCh := make(chan string, 4)
	pods := `{"items":[
		{"metadata":{"name":"backup-1","namespace":"ns1"},
		 "status":{"phase":"Failed",
			  "containerStatuses":[
				{"name":"backup","ready":false,"restartCount":0,
				 "state":{"terminated":{"exitCode":1,"reason":"Error",
					"message":"checksum mismatch","finishedAt":"2026-01-02T03:04:05Z"}}}]}}
	]}`
	srv := newEnrichTestServer(pods, "backup failed: checksum mismatch\n", logCh)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubePodFailed", "namespace": "ns1", "pod": "backup-1"}}},
		Namespaces: []string{"ns1"},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, nil)

	if len(en.UnhealthyPods) == 0 {
		t.Fatalf("expected a failed one-shot pod to be listed unhealthy, got none")
	}
	found := false
	for _, d := range en.ContainerDiagnostics {
		if strings.Contains(d, "backup-1") &&
			strings.Contains(d, "container backup") &&
			strings.Contains(d, "exit=1") &&
			strings.Contains(d, "reason=Error") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a terminated diagnostic for the one-shot container, got: %v", en.ContainerDiagnostics)
	}
	select {
	case q := <-logCh:
		if !strings.Contains(q, "container=backup") {
			t.Errorf("log request must name the failing container, got: %s", q)
		}
		if p := queryPrevious(q); p != "" {
			t.Errorf("a one-shot container must use the current log, got previous=%s in: %s", p, q)
		}
	default:
		t.Fatal("expected a log fetch for the failing one-shot container")
	}
	if prov, ok := en.PodLogProvenance["ns1/backup-1"]; !ok {
		t.Errorf("expected provenance recorded for the one-shot pod, got: %v", en.PodLogProvenance)
	} else if prov.Stream != "current" {
		t.Errorf("provenance stream = %q, want current", prov.Stream)
	}
}

// Issue #128 review regression: the rendered evidence for a one-shot Job
// must NOT call the current log a "previous container tail", and must
// surface the diagnostic line that says why the container ended.
func TestRender_oneShotContainerEvidenceLabelsCurrentStream(t *testing.T) {
	g := Group{
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubePodFailed", "namespace": "ns1", "pod": "backup-1"}}},
		Namespaces: []string{"ns1"},
	}
	en := Enrichment{
		PodLogs: map[string]string{"ns1/backup-1": "checksum mismatch"},
		PodLogProvenance: map[string]podLogProvenance{
			"ns1/backup-1": {Container: "backup", Stream: "current"},
		},
		ContainerDiagnostics: []string{"ns1/backup-1: container backup terminated exit=1 reason=Error at 2026-01-02T03:04:05Z — checksum mismatch"},
		// The alert names ns1/backup-1, so the same evidence is subject-scoped
		// and renders in the direct tier; the fields above serve Discord.
		SubjectPodLogs: map[string]string{"ns1/backup-1": "checksum mismatch"},
		SubjectPodLogProvenance: map[string]podLogProvenance{
			"ns1/backup-1": {Container: "backup", Stream: "current"},
		},
		SubjectContainerDiagnostics: []string{"ns1/backup-1: container backup terminated exit=1 reason=Error at 2026-01-02T03:04:05Z — checksum mismatch"},
	}
	body := renderEvidence(Report{Group: g, Enrichment: en})

	// The reviewer-flagged regression: never call a current log a previous
	// container tail.
	if strings.Contains(body, "previous container tail") {
		t.Errorf("rendered evidence still labels the section 'previous container tail':\n%s", body)
	}
	// The per-entry header must identify container + current stream so the
	// model and the operator know what they are looking at.
	if !strings.Contains(body, "container backup, current stream") {
		t.Errorf("rendered evidence missing 'container backup, current stream' header:\n%s", body)
	}
	// The diagnostic line — the short path to root cause for a one-shot Job —
	// must reach the model before it is called.
	if !strings.Contains(body, "container backup terminated exit=1 reason=Error") {
		t.Errorf("rendered evidence missing the terminated-container diagnostic:\n%s", body)
	}

	// Discord delivery: same provenance requirement, same labels.
	discord := discordDescription(&Config{}, Report{Group: g, Enrichment: en})
	if strings.Contains(discord, "previous container tail") {
		t.Errorf("discord description still labels logs 'previous container tail':\n%s", discord)
	}
	if !strings.Contains(discord, "container backup, current stream") {
		t.Errorf("discord description missing container/stream provenance:\n%s", discord)
	}
}

// Issue #128 review: the provenance the renderer must carry is the SELECTED
// stream, and the one-shot case is not the only one. A restarted (CrashLoop)
// container is logged through the *previous* stream, so its per-entry header
// must say "previous stream", not "current" — the mirror image of the
// one-shot regression above, asserting the label follows the real selection in
// both the model-visible evidence and the Discord delivery.
func TestRender_restartedContainerEvidenceLabelsPreviousStream(t *testing.T) {
	g := Group{
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubePodRestart", "namespace": "ns1", "pod": "flaky-1"}}},
		Namespaces: []string{"ns1"},
	}
	en := Enrichment{
		PodLogs: map[string]string{"ns1/flaky-1": "panic: nil"},
		PodLogProvenance: map[string]podLogProvenance{
			"ns1/flaky-1": {Container: "app", Stream: "previous"},
		},
		ContainerDiagnostics: []string{"ns1/flaky-1: container app terminated exit=1 reason=Error at 2026-01-02T03:04:05Z"},
		// Subject-scoped mirror for renderEvidence; the fields above serve
		// Discord.
		SubjectPodLogs: map[string]string{"ns1/flaky-1": "panic: nil"},
		SubjectPodLogProvenance: map[string]podLogProvenance{
			"ns1/flaky-1": {Container: "app", Stream: "previous"},
		},
		SubjectContainerDiagnostics: []string{"ns1/flaky-1: container app terminated exit=1 reason=Error at 2026-01-02T03:04:05Z"},
	}
	body := renderEvidence(Report{Group: g, Enrichment: en})
	if !strings.Contains(body, "container app, previous stream") {
		t.Errorf("rendered evidence missing 'container app, previous stream' header:\n%s", body)
	}
	if strings.Contains(body, "current stream") {
		t.Errorf("rendered evidence labels a restarted container's log 'current stream':\n%s", body)
	}

	discord := discordDescription(&Config{}, Report{Group: g, Enrichment: en})
	if !strings.Contains(discord, "container app, previous stream") {
		t.Errorf("discord description missing 'container app, previous stream' provenance:\n%s", discord)
	}
	if strings.Contains(discord, "current stream") {
		t.Errorf("discord description labels a restarted container's log 'current stream':\n%s", discord)
	}
}

// Issue #128 review (minor, enrich.go:1133): fetchPodLogs records a provenance
// entry for every spec, even when the spec names no container. The renderers
// guard with `p.Container != ""`, so an empty-container spec must be dropped
// silently: neither the evidence nor the chat may print a "container , ...
// stream" header for it. This pins that guard — a regression that rendered
// the empty-container provenance as a malformed header would be caught here.
func TestRender_emptyContainerProvenanceIsNotVisible(t *testing.T) {
	g := Group{
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubePodFailed", "namespace": "ns1", "pod": "backup-1"}}},
		Namespaces: []string{"ns1"},
	}
	en := Enrichment{
		PodLogs: map[string]string{"ns1/backup-1": "checksum mismatch"},
		PodLogProvenance: map[string]podLogProvenance{
			// Container is empty: the renderers must not surface it.
			"ns1/backup-1": {Container: "", Stream: "current"},
		},
		SubjectPodLogs: map[string]string{"ns1/backup-1": "checksum mismatch"},
		SubjectPodLogProvenance: map[string]podLogProvenance{
			"ns1/backup-1": {Container: "", Stream: "current"},
		},
	}
	body := renderEvidence(Report{Group: g, Enrichment: en})
	// The pod key and the log must still reach the model...
	if !strings.Contains(body, "## ns1/backup-1") {
		t.Fatalf("rendered evidence missing the pod header:\n%s", body)
	}
	if !strings.Contains(body, "checksum mismatch") {
		t.Fatalf("rendered evidence missing the log body:\n%s", body)
	}
	// ...and the container/stream provenance header must not, because the
	// provenance names no container. Match the malformed header form
	// ("container <name>, <stream> stream:") rather than the word alone, since
	// the tier headings legitimately say "container terminations".
	if strings.Contains(body, "container ,") || strings.Contains(body, "container  ") {
		t.Errorf("rendered evidence leaked a container provenance header for an empty-container spec:\n%s", body)
	}
	if strings.Contains(body, "stream:") {
		t.Errorf("rendered evidence leaked a stream provenance header for an empty-container spec:\n%s", body)
	}
	discord := discordDescription(&Config{}, Report{Group: g, Enrichment: en})
	if !strings.Contains(discord, "`ns1/backup-1`") {
		t.Fatalf("discord description missing the plain pod label:\n%s", discord)
	}
	if strings.Contains(discord, "container") {
		t.Errorf("discord description leaked a container provenance label for an empty-container spec:\n%s", discord)
	}
	if strings.Contains(discord, "stream") {
		t.Errorf("discord description leaked a stream provenance label for an empty-container spec:\n%s", discord)
	}
}

// Issue #128: a restarted (CrashLoop) container must have its log fetched
// as the PREVIOUS stream and the failure evidence comes from its last run.
func TestEnrich_restartedContainerUsesPreviousLog(t *testing.T) {
	logCh := make(chan string, 4)
	pods := `{"items":[
		{"metadata":{"name":"flaky-1","namespace":"ns1"},
		 "status":{"phase":"Running",
			  "containerStatuses":[
				{"name":"app","ready":false,"restartCount":3,
				 "state":{"waiting":{"reason":"CrashLoopBackOff"}},
				 "lastState":{"terminated":{"exitCode":1,"reason":"Error",
					"message":"panic: nil","finishedAt":"2026-01-02T03:04:05Z"}}}]}}
	]}`
	srv := newEnrichTestServer(pods, "panic: nil\n", logCh)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubePodRestart", "namespace": "ns1", "pod": "flaky-1"}}},
		Namespaces: []string{"ns1"},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, nil)

	found := false
	for _, d := range en.ContainerDiagnostics {
		if strings.Contains(d, "flaky-1") && strings.Contains(d, "exit=1") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a last-run diagnostic for the crashed container, got: %v", en.ContainerDiagnostics)
	}
	select {
	case q := <-logCh:
		if !strings.Contains(q, "container=app") {
			t.Errorf("log request must name the failing container, got: %s", q)
		}
		if p := queryPrevious(q); p != "true" {
			t.Errorf("a restarted container must use the previous log, got previous=%q in: %s", p, q)
		}
	default:
		t.Fatal("expected a log fetch for the restarted container")
	}
	if prov, ok := en.PodLogProvenance["ns1/flaky-1"]; !ok {
		t.Errorf("expected provenance recorded for the restarted pod, got: %v", en.PodLogProvenance)
	} else if prov.Stream != "previous" {
		t.Errorf("provenance stream = %q, want previous", prov.Stream)
	}
}

// Issue #128: a successful (Succeeded) one-shot pod must not be reported as
// a failure and must not have its log fetched (no diagnostic, no stream).
func TestEnrich_succeededContainerIsSkipped(t *testing.T) {
	var logHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/log"):
			logHits++
			w.Write([]byte("ok\n"))
		default:
			_, _ = io.WriteString(w, `{"items":[
				{"metadata":{"name":"done-1","namespace":"ns1"},
				 "status":{"phase":"Succeeded",
					  "containerStatuses":[
						{"name":"job","ready":false,"restartCount":0,
						 "state":{"terminated":{"exitCode":0,"reason":"Completed",
							"finishedAt":"2026-01-02T03:04:05Z"}}}]}}
			]}`)
		}
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubePodCompleted", "namespace": "ns1", "pod": "done-1"}}},
		Namespaces: []string{"ns1"},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, nil)

	for _, p := range en.UnhealthyPods {
		if strings.Contains(p, "done-1") {
			t.Errorf("Succeeded pod must not be listed unhealthy, got %q", p)
		}
	}
	if len(en.ContainerDiagnostics) != 0 {
		t.Errorf("Succeeded pod must produce no container diagnostic, got %v", en.ContainerDiagnostics)
	}
	if logHits != 0 {
		t.Errorf("Succeeded pod's log must not be fetched, got %d fetches", logHits)
	}
	if len(en.PodLogProvenance) != 0 {
		t.Errorf("Succeeded pod must not record provenance, got %v", en.PodLogProvenance)
	}
}

// Issue #128: a multi-container pod where only one container failed must be
// logged through the failing container (named explicitly), not the apiserver's
// default-container choice.
func TestEnrich_multiContainerLogsFailingContainer(t *testing.T) {
	var gotContainer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/log"):
			gotContainer = r.URL.Query().Get("container")
			w.Write([]byte("sidecar failed: bad certificate\n"))
		case strings.HasSuffix(r.URL.Path, "/pods"):
			_, _ = io.WriteString(w, `{"items":[
				{"metadata":{"name":"multi-1","namespace":"ns1"},
				 "status":{"phase":"Failed",
					  "containerStatuses":[
						{"name":"main","ready":true,"restartCount":0,
						 "state":{"running":{"startedAt":"2026-01-02T03:00:00Z"}}},
						{"name":"sidecar","ready":false,"restartCount":0,
						 "state":{"terminated":{"exitCode":1,"reason":"Error",
							"message":"bad certificate","finishedAt":"2026-01-02T03:04:05Z"}}}]}}
			]}`)
		default:
			_, _ = io.WriteString(w, `{"items":[]}`)
		}
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubePodFailed", "namespace": "ns1", "pod": "multi-1"}}},
		Namespaces: []string{"ns1"},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, nil)

	if gotContainer != "sidecar" {
		t.Errorf("expected the failing container (sidecar) to be logged, got %q", gotContainer)
	}
	found := false
	for _, d := range en.ContainerDiagnostics {
		if strings.Contains(d, "multi-1") && strings.Contains(d, "container sidecar") &&
			strings.Contains(d, "exit=1") && strings.Contains(d, "reason=Error") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a diagnostic for the failing sidecar container, got %v", en.ContainerDiagnostics)
	}
	if prov, ok := en.PodLogProvenance["ns1/multi-1"]; !ok {
		t.Errorf("expected provenance recorded for the multi-container pod, got: %v", en.PodLogProvenance)
	} else if prov.Container != "sidecar" {
		t.Errorf("provenance container = %q, want sidecar", prov.Container)
	}
}

// Issue #128: log-fetch failures must not stop the digest — enrichment still
// returns the other evidence (the diagnostic) when the log endpoint 404s.
func TestEnrich_logFailureIsNonFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/log"):
			http.Error(w, "no such container", http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/pods"):
			_, _ = io.WriteString(w, `{"items":[
				{"metadata":{"name":"backup-1","namespace":"ns1"},
				 "status":{"phase":"Failed",
					  "containerStatuses":[
						{"name":"backup","ready":false,"restartCount":0,
						 "state":{"terminated":{"exitCode":1,"reason":"Error",
							"message":"checksum","finishedAt":"2026-01-02T03:04:05Z"}}}]}}
			]}`)
		default:
			_, _ = io.WriteString(w, `{"items":[]}`)
		}
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubePodFailed", "namespace": "ns1", "pod": "backup-1"}}},
		Namespaces: []string{"ns1"},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, nil)

	found := false
	for _, d := range en.ContainerDiagnostics {
		if strings.Contains(d, "backup-1") && strings.Contains(d, "exit=1") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the diagnostic to survive a log-fetch failure, got %v", en.ContainerDiagnostics)
	}
	if len(en.PodLogs) != 0 {
		t.Errorf("expected no PodLogs after a 404, got %v", en.PodLogs)
	}
}

// newEnrichTestServer is a helper that serves the pods listing for the
// group's namespaces and the pod log endpoint (the caller records each log
// request). Everything else is empty so no other enrichment side-effects fire.
func newEnrichTestServer(podsJSON, logBody string, logReqCh chan<- string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/pods"):
			_, _ = io.WriteString(w, podsJSON)
		case strings.HasSuffix(r.URL.Path, "/log"):
			logReqCh <- r.URL.RawQuery
			_, _ = io.WriteString(w, logBody)
		default:
			_, _ = io.WriteString(w, `{"items":[]}`)
		}
	}))
}

// queryPrevious returns the "previous" query parameter from an encoded
// query string, for asserting which log stream was requested.
func queryPrevious(rawQuery string) string {
	for _, kv := range strings.Split(rawQuery, "&") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "previous" {
			return v
		}
	}
	return ""
}

// TestResolveCommitRelevanceFluxAndGitHub is the end-to-end test for issue
// #135: a pod with the Flux kustomize annotations, a Kustomization with a
// github.com GitRepository, and a GitHub commit whose files DO touch the
// workload path must produce a CommitRelevance with State == "touches".
// The test wires up three servers — the kube API, the github.com API —
// and asserts the renderer surfaces the matching files (inside the
// untrusted fence) and the commit message.
func TestResolveCommitRelevanceFluxAndGitHub(t *testing.T) {
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	var kubeHits, ghHits atomic.Int32
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kubeHits.Add(1)
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/payments"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/payments","sourceRef":{"name":"payments","kind":"GitRepository"}},"status":{"lastAppliedRevision":"refs/heads/main@sha1:`+validSHA+`"}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/payments"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/owner/repo"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer kubeSrv.Close()
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ghHits.Add(1)
		// Path: /repos/owner/repo/commits/<sha>
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 5 || parts[4] != validSHA {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"sha":"`+validSHA+`","commit":{"message":"bump image tag"},"files":[{"filename":"apps/payments/kustomization.yaml"},{"filename":"apps/payments/deployment.yaml"}]}`)
	}))
	defer ghSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL}
	gh := &gitHubClient{token: "t", repo: "owner/repo", hc: ghSrv.Client(), apiURL: ghSrv.URL}
	pods := []podRef{{
		Name:      "p",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "payments",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	got := k.resolveCommitRelevance(context.Background(), gh, pods)
	if len(got) != 1 {
		t.Fatalf("expected 1 CommitRelevance, got %d", len(got))
	}
	rel := got[0]
	if rel.State != commitRelevanceTouches {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceTouches, rel.Reason)
	}
	if rel.WorkloadPath != "apps/payments" {
		t.Errorf("workload path = %q, want %q", rel.WorkloadPath, "apps/payments")
	}
	if rel.Revision != "refs/heads/main@sha1:"+validSHA {
		t.Errorf("revision = %q", rel.Revision)
	}
	if len(rel.MatchingPaths) != 2 {
		t.Errorf("matching paths = %v, want 2 entries", rel.MatchingPaths)
	}
	if rel.CommitMessage != "bump image tag" {
		t.Errorf("commit message = %q, want %q", rel.CommitMessage, "bump image tag")
	}
	if kubeHits.Load() == 0 || ghHits.Load() == 0 {
		t.Errorf("expected both kube and github hits, got kube=%d github=%d", kubeHits.Load(), ghHits.Load())
	}

	// And the renderer must fence the matching files (they are quoted from
	// a third-party commit) while leaving the State line outside the fence.
	en := Enrichment{CommitRelevance: got}
	evidence := renderEvidence(Report{Enrichment: en})
	if !strings.Contains(evidence, "Recent reconciled commit (GitHub):") {
		t.Errorf("evidence missing header:\n%s", evidence)
	}
	if !strings.Contains(evidence, "touches workload: apps/payments") {
		t.Errorf("evidence missing state line:\n%s", evidence)
	}
	if strings.Count(evidence, untrustedBegin) < 2 {
		// one for alerts, one for matching files
		t.Errorf("expected matching files inside untrusted fence:\n%s", evidence)
	}
}

// TestResolveCommitRelevanceDoesNotTouch covers the motivating case for
// #135 end-to-end: the commit the Kustomization is reconciled at only
// touches an unrelated workload, so the digest must say so explicitly
// rather than hinting at a deploy.
func TestResolveCommitRelevanceDoesNotTouch(t *testing.T) {
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/payments"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/payments","sourceRef":{"name":"payments","kind":"GitRepository"}},"status":{"lastAppliedRevision":"refs/heads/main@sha1:`+validSHA+`"}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/payments"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/owner/repo"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer kubeSrv.Close()
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 5 || parts[4] != validSHA {
			http.NotFound(w, r)
			return
		}
		// A commit that touches an unrelated path.
		_, _ = io.WriteString(w, `{"sha":"`+validSHA+`","commit":{"message":"bump orders image"},"files":[{"filename":"apps/orders/kustomization.yaml"}]}`)
	}))
	defer ghSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL}
	gh := &gitHubClient{token: "t", repo: "owner/repo", hc: ghSrv.Client(), apiURL: ghSrv.URL}
	pods := []podRef{{
		Name:      "p",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "payments",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	got := k.resolveCommitRelevance(context.Background(), gh, pods)
	if len(got) != 1 {
		t.Fatalf("expected 1 CommitRelevance, got %d", len(got))
	}
	rel := got[0]
	if rel.State != commitRelevanceDoesNotTouch {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceDoesNotTouch, rel.Reason)
	}
	if len(rel.MatchingPaths) != 0 {
		t.Errorf("expected no matching paths, got %v", rel.MatchingPaths)
	}
	if rel.CommitMessage != "bump orders image" {
		t.Errorf("commit message = %q, want %q", rel.CommitMessage, "bump orders image")
	}

	// The renderer must say "does NOT touch" — never phrase it as a
	// likely trigger.
	en := Enrichment{CommitRelevance: got}
	evidence := renderEvidence(Report{Enrichment: en})
	if !strings.Contains(evidence, "does NOT touch workload") {
		t.Errorf("evidence should explicitly say 'does NOT touch', got:\n%s", evidence)
	}
	joined := strings.ToLower(evidence)
	for _, w := range []string{"trigger", "deploy", "rolled out"} {
		if strings.Contains(joined, w) {
			t.Errorf("evidence must not call a non-touching commit a %q, got:\n%s", w, evidence)
		}
	}
}

// TestResolveCommitRelevanceComponentRelativeToPath is the integration
// regression for the Flux Kustomization components contract: spec.components
// are relative to the Kustomization's spec.path, not to the repo root. A
// component "../shared" under path "apps/payments/prod" resolves to
// "apps/payments/shared", and a commit touching that resolved path must be
// classified as "touches" the workload.
func TestResolveCommitRelevanceComponentRelativeToPath(t *testing.T) {
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/payments"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/payments/prod","sourceRef":{"name":"payments","kind":"GitRepository"},"components":["../shared"]},"status":{"lastAppliedRevision":"refs/heads/main@sha1:`+validSHA+`"}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/payments"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/owner/repo"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer kubeSrv.Close()
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 5 || parts[4] != validSHA {
			http.NotFound(w, r)
			return
		}
		// The commit touches only the shared component's directory, which
		// is a sibling of the workload path: resolved it is
		// apps/payments/shared, not "shared" and not
		// apps/payments/prod/shared.
		_, _ = io.WriteString(w, `{"sha":"`+validSHA+`","commit":{"message":"tune shared config"},"files":[{"filename":"apps/payments/shared/tuning.yaml"}]}`)
	}))
	defer ghSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL}
	gh := &gitHubClient{token: "t", repo: "owner/repo", hc: ghSrv.Client(), apiURL: ghSrv.URL}
	pods := []podRef{{
		Name:      "p",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "payments",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	got := k.resolveCommitRelevance(context.Background(), gh, pods)
	if len(got) != 1 {
		t.Fatalf("expected 1 CommitRelevance, got %d", len(got))
	}
	rel := got[0]
	if rel.State != commitRelevanceTouches {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceTouches, rel.Reason)
	}
	if len(rel.ComponentPaths) != 1 || rel.ComponentPaths[0] != "apps/payments/shared" {
		t.Fatalf("component paths = %v, want [apps/payments/shared]", rel.ComponentPaths)
	}
	if len(rel.MatchingPaths) != 1 || rel.MatchingPaths[0] != "apps/payments/shared/tuning.yaml" {
		t.Fatalf("matching paths = %v, want [apps/payments/shared/tuning.yaml]", rel.MatchingPaths)
	}
}

// TestResolveCommitRelevanceNonGitHubRepo: a workload whose GitRepository
// is hosted outside GitHub must degrade to State == "unknown" so the
// digest never claims a non-GitHub lookup produced a result.
func TestResolveCommitRelevanceNonGitHubRepo(t *testing.T) {
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/payments"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/payments","sourceRef":{"name":"payments","kind":"GitRepository"}},"status":{"lastAppliedRevision":"refs/heads/main@sha1:`+validSHA+`"}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/payments"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://gitlab.example.com/owner/repo"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer kubeSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL}
	gh := &gitHubClient{token: "t", repo: "owner/repo", hc: &http.Client{}, apiURL: "http://unused.invalid"}
	pods := []podRef{{
		Name:      "p",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "payments",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	got := k.resolveCommitRelevance(context.Background(), gh, pods)
	if len(got) != 1 {
		t.Fatalf("expected 1 CommitRelevance, got %d", len(got))
	}
	if got[0].State != commitRelevanceUnknown {
		t.Fatalf("state = %q, want %q (reason=%q)", got[0].State, commitRelevanceUnknown, got[0].Reason)
	}
	if !strings.Contains(strings.ToLower(got[0].Reason), "github") {
		t.Errorf("unknown reason should mention the host check, got %q", got[0].Reason)
	}
}

// TestEnrichWiringGitHubEndToEnd exercises the full Enrich path: pass
// a gitHubClient in, get a CommitRelevance out, with the kube API and
// the GitHub API both stubbed.
func TestEnrichWiringGitHubEndToEnd(t *testing.T) {
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/payments"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/payments","sourceRef":{"name":"payments","kind":"GitRepository"}},"status":{"lastAppliedRevision":"refs/heads/main@sha1:`+validSHA+`"}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/payments"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/owner/repo"}}`)
		case strings.HasSuffix(r.URL.Path, "/pods"):
			_, _ = io.WriteString(w, `{"items":[{"metadata":{"name":"p","namespace":"ns-a","annotations":{"kustomize.toolkit.fluxcd.io/name":"payments","kustomize.toolkit.fluxcd.io/namespace":"flux-system"}},"spec":{"nodeName":"n1"},"status":{"phase":"Failed","containerStatuses":[{"name":"c","ready":false,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer kubeSrv.Close()
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 5 || parts[4] != validSHA {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"sha":"`+validSHA+`","commit":{"message":"bump image"},"files":[{"filename":"apps/payments/kustomization.yaml"}]}`)
	}))
	defer ghSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL, cluster: "default"}
	gh := &gitHubClient{token: "t", repo: "owner/repo", hc: ghSrv.Client(), apiURL: ghSrv.URL}
	g := Group{
		Key:        "KubePodCrashLooping",
		Cluster:    "default",
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{{
			Labels:   map[string]string{"alertname": "KubePodCrashLooping", "namespace": "ns-a", "pod": "p"},
			StartsAt: time.Now().Add(-time.Minute),
		}},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, gh)
	if len(en.CommitRelevance) != 1 {
		t.Fatalf("expected 1 CommitRelevance from Enrich, got %d (enrichment=%+v)", len(en.CommitRelevance), en)
	}
	if en.CommitRelevance[0].State != commitRelevanceTouches {
		t.Fatalf("state = %q, want %q", en.CommitRelevance[0].State, commitRelevanceTouches)
	}
}

// TestEnrichNoGitHubClientLeavesRelevanceEmpty verifies that the common
// case (GITHUB_REPO/GITHUB_TOKEN unset) leaves CommitRelevance empty so
// the renderer does not pretend a check happened.
func TestEnrichNoGitHubClientLeavesRelevanceEmpty(t *testing.T) {
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pod listing returns a pod with Flux annotations.
		if strings.HasSuffix(r.URL.Path, "/pods") {
			_, _ = io.WriteString(w, `{"items":[{"metadata":{"name":"p","namespace":"ns-a","annotations":{"kustomize.toolkit.fluxcd.io/name":"payments","kustomize.toolkit.fluxcd.io/namespace":"flux-system"}},"spec":{"nodeName":"n1"},"status":{"phase":"Failed","containerStatuses":[{"name":"c","ready":false,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer kubeSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL, cluster: "default"}
	g := Group{
		Key:        "KubePodCrashLooping",
		Cluster:    "default",
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{{
			Labels:   map[string]string{"alertname": "KubePodCrashLooping", "namespace": "ns-a", "pod": "p"},
			StartsAt: time.Now().Add(-time.Minute),
		}},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, nil)
	if len(en.CommitRelevance) != 0 {
		t.Fatalf("expected CommitRelevance to be empty without gh, got %d entries: %+v", len(en.CommitRelevance), en.CommitRelevance)
	}
}

// --- Declared execution identity and PVC relationships (issue #132) ---

// podItemFromJSON decodes a single-item pod list into one podItem, for tests
// that only need one pod.
func podItemFromJSON(t *testing.T, raw string) podItem {
	t.Helper()
	var list podList
	if err := json.Unmarshal([]byte(`{"items":[`+raw+`]}`), &list); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(list.Items))
	}
	return list.Items[0]
}

// A pod that declares its execution identity at the pod level (not the
// container level) must have those fields captured, so a permission hypothesis
// can be grounded in what the pod declared.
func TestPodItemPodLevelSecurityContext(t *testing.T) {
	p := podItemFromJSON(t, `{
		"metadata":{"name":"mover","namespace":"ns1"},
		"spec":{"securityContext":{"runAsUser":1000,"runAsGroup":2000,"fsGroup":3000,"runAsNonRoot":true}},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,"restartCount":2,
			 "state":{"waiting":{"reason":"CrashLoopBackOff"}}}
		]}
	}`)
	if p.Spec.Security == nil {
		t.Fatal("expected a pod-level securityContext, got nil")
	}
	u, g, fg, nr := p.Spec.Security.format()
	if u != "1000" || g != "2000" || fg != "3000" || nr != "true" {
		t.Errorf("pod securityContext = (%q,%q,%q,%q), want (1000,2000,3000,true)", u, g, fg, nr)
	}
}

// The container securityContext and volumeMounts live under spec.containers,
// not status.containerStatuses: this is the exact shape the apiserver returns,
// and the one the feature must read.
func TestPodItemContainerOverridesPodIdentity(t *testing.T) {
	p := podItemFromJSON(t, `{
		"metadata":{"name":"mover","namespace":"ns1"},
		"spec":{
			"securityContext":{"runAsUser":1000,"runAsGroup":2000,"fsGroup":3000,"runAsNonRoot":true},
			"containers":[{"name":"mover",
				"securityContext":{"runAsUser":4000,"runAsNonRoot":false},
				"volumeMounts":[{"name":"data","mountPath":"/data","readOnly":false}]}],
			"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]
		},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,"restartCount":1,
			 "state":{"waiting":{"reason":"CrashLoopBackOff"}}}
		]}
	}`)
	cs := p.containerSpec("mover")
	if cs == nil {
		t.Fatal("expected the spec container mover to be captured from spec.containers")
	}
	eff := cs.effective(p.Spec.Security)
	u, g, fg, nr := eff.format()
	// runAsUser/RunAsNonRoot overridden by the container, runAsGroup/fsGroup
	// inherited from the pod.
	if u != "4000" || g != "2000" || fg != "3000" || nr != "false" {
		t.Errorf("effective = (%q,%q,%q,%q), want (4000,2000,3000,false)", u, g, fg, nr)
	}
}

// When neither the pod nor the container declares anything, every field reads
// "unset" - it must not be guessed as root from the image.
func TestPodItemAllIdentityUnset(t *testing.T) {
	p := podItemFromJSON(t, `{
		"metadata":{"name":"mover","namespace":"ns1"},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,
			 "state":{"terminated":{"exitCode":1,"reason":"Error"}}}
		]}
	}`)
	if p.Spec.Security != nil {
		t.Fatalf("expected no pod securityContext, got %v", *p.Spec.Security)
	}
	eff := p.containerSpec("mover").effective(p.Spec.Security)
	u, g, fg, nr := eff.format()
	if u != "unset" || g != "unset" || fg != "unset" || nr != "unset" {
		t.Errorf("unset pod = (%q,%q,%q,%q), want (unset,unset,unset,unset)", u, g, fg, nr)
	}
}

// runAsNonRoot must keep its three states: an explicit false, an explicit true,
// and an absent value that stays unset rather than collapsing to false.
func TestPodItemRunAsNonRootThreeState(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{"unset", `{"runAsUser":100}`, "unset"},
		{"true", `{"runAsNonRoot":true}`, "true"},
		{"false", `{"runAsNonRoot":false}`, "false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := podItemFromJSON(t, `{
				"metadata":{"name":"mover","namespace":"ns1"},
				"spec":{"containers":[{"name":"mover","securityContext":`+tc.json+`}]},
				"status":{"phase":"Failed","containerStatuses":[
					{"name":"mover","ready":false,"state":{"waiting":{"reason":"Error"}}}
				]}
			}`)
			eff := p.containerSpec("mover").effective(nil)
			_, _, _, nr := eff.format()
			if nr != tc.want {
				t.Errorf("runAsNonRoot = %q, want %q", nr, tc.want)
			}
		})
	}
}

// A container securityContext present but with a single field must still leave
// the unset fields unset rather than defaulting them.
func TestPodItemPartialContainerIdentity(t *testing.T) {
	p := podItemFromJSON(t, `{
		"metadata":{"name":"mover","namespace":"ns1"},
		"spec":{"containers":[{"name":"mover",
			"securityContext":{"runAsUser":100}}]},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,"state":{"waiting":{"reason":"Error"}}}
		]}
	}`)
	eff := p.containerSpec("mover").effective(nil)
	u, g, fg, nr := eff.format()
	if u != "100" || g != "unset" || fg != "unset" || nr != "unset" {
		t.Errorf("partial = (%q,%q,%q,%q), want (100,unset,unset,unset)", u, g, fg, nr)
	}
}

// A volume that references a PVC must be mapped to its claim name; a non-PVC
// volume (emptyDir) must not fabricate a claim.
func TestPodItemVolumeToClaim(t *testing.T) {
	p := podItemFromJSON(t, `{
		"metadata":{"name":"mover","namespace":"ns1"},
		"spec":{
			"containers":[{"name":"mover","volumeMounts":[
				{"name":"data","mountPath":"/data","readOnly":false},
				{"name":"tmp","mountPath":"/tmp","readOnly":false}]}],
			"volumes":[
				{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}},
				{"name":"tmp","emptyDir":{}}]
		},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,"state":{"terminated":{"exitCode":1,"reason":"Error"}}}
		]}
	}`)
	mounts := p.mount()
	if len(mounts) != 1 {
		t.Fatalf("expected exactly the PVC claim, got %v", mounts)
	}
	m, ok := mounts["data-claim"]
	if !ok {
		t.Fatalf("missing data-claim in %v", mounts)
	}
	if m.Container != "mover" || m.Path != "/data" || m.ReadOnly {
		t.Errorf("mount = %+v, want container=mover path=/data read-only=false", m)
	}
}

// A pod with only non-PVC volumes has no claim, so it is not a same-claim
// sibling of anything.
func TestPodItemNoPVCNoClaim(t *testing.T) {
	p := podItemFromJSON(t, `{
		"metadata":{"name":"mover","namespace":"ns1"},
		"spec":{
			"containers":[{"name":"mover","volumeMounts":[{"name":"tmp","mountPath":"/tmp"}]}],
			"volumes":[{"name":"tmp","emptyDir":{}}]
		},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,"state":{"terminated":{"exitCode":1,"reason":"Error"}}}
		]}
	}`)
	if len(p.claims()) != 0 {
		t.Errorf("expected no claims, got %v", p.claims())
	}
}

// A container that is in the running state is not failing; a container whose
// only state is non-running is failing. Succeeded pods are never failing.
func TestPodItemFailing(t *testing.T) {
	failing := podItemFromJSON(t, `{
		"metadata":{"name":"a","namespace":"ns1"},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,"state":{"waiting":{"reason":"CrashLoopBackOff"}}},
			{"name":"sidecar","ready":false,"state":{"terminated":{"exitCode":1,"reason":"Error"}}}
		]}
	}`)
	if !failing.failing()["mover"] || !failing.failing()["sidecar"] {
		t.Errorf("expected both containers failing, got %v", failing.failing())
	}

	healthy := podItemFromJSON(t, `{
		"metadata":{"name":"b","namespace":"ns1"},
		"status":{"phase":"Running","containerStatuses":[
			{"name":"app","ready":true,"state":{"running":{}}}
		]}
	}`)
	if len(healthy.failing()) != 0 {
		t.Errorf("expected no failing container in a healthy Running pod, got %v", healthy.failing())
	}

	succeeded := podItemFromJSON(t, `{
		"metadata":{"name":"c","namespace":"ns1"},
		"status":{"phase":"Succeeded","containerStatuses":[
			{"name":"job","ready":false,"state":{"terminated":{"exitCode":0,"reason":"Completed"}}}
		]}
	}`)
	if len(succeeded.failing()) != 0 {
		t.Errorf("a Succeeded pod is never failing, got %v", succeeded.failing())
	}
}

// identityHarness serves a distinct pod list per namespace so a test can put
// same-named claims in two namespaces and assert they are not conflated.
func identityHarness(t *testing.T, byNS map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/nodes"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.HasSuffix(p, "/pods"):
			ns := ""
			parts := strings.Split(strings.Trim(p, "/"), "/")
			for i := 0; i+1 < len(parts); i++ {
				if parts[i] == "namespaces" {
					ns = parts[i+1]
				}
			}
			if body, ok := byNS[ns]; ok {
				_, _ = io.WriteString(w, body)
				return
			}
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.Contains(p, "/events"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		default:
			_, _ = io.WriteString(w, `{"items":[]}`)
		}
	}))
}

// A failed pod the alert names must yield its effective declared identity and
// PVC mount, and a healthy pod mounting the same claim in the same namespace
// must appear as comparison context; an unrelated claim must not.
func TestEnrichPodIdentityAndSameClaimSibling(t *testing.T) {
	ns1 := `{
		"items":[
			{"metadata":{"name":"mover","namespace":"ns1"},
			 "spec":{
				"securityContext":{"runAsUser":1000,"runAsGroup":2000,"fsGroup":3000,"runAsNonRoot":true},
				"containers":[{"name":"mover",
					"securityContext":{"runAsUser":4000,"runAsNonRoot":false},
					"volumeMounts":[{"name":"data","mountPath":"/data","readOnly":false}]}],
				"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]},
			 "status":{"phase":"Failed","containerStatuses":[
				{"name":"mover","ready":false,"restartCount":0,
				 "state":{"terminated":{"exitCode":1,"reason":"Error"}}}]}},
			{"metadata":{"name":"app-xyz","namespace":"ns1"},
			 "spec":{
				"securityContext":{"fsGroup":3000,"runAsNonRoot":true},
				"containers":[{"name":"app",
					"securityContext":{"runAsUser":2000},
					"volumeMounts":[{"name":"data","mountPath":"/data","readOnly":true}]}],
				"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]},
			 "status":{"phase":"Running","containerStatuses":[
				{"name":"app","ready":true,"state":{"running":{}}}]}},
			{"metadata":{"name":"unrelated","namespace":"ns1"},
			 "spec":{
				"containers":[{"name":"u","volumeMounts":[{"name":"other","mountPath":"/other"}]}],
				"volumes":[{"name":"other","persistentVolumeClaim":{"claimName":"other-claim"}}]},
			 "status":{"phase":"Running","containerStatuses":[
				{"name":"u","ready":true,"state":{"running":{}}}]}}
		]}`
	srv := identityHarness(t, map[string]string{"ns1": ns1})
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubePodCrashLooping", "namespace": "ns1", "pod": "mover",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	id, ok := en.PodID["ns1/mover"]
	if !ok {
		t.Fatalf("expected an identity line for ns1/mover, got %v", en.PodID)
	}
	for _, want := range []string{"runAsUser=4000", "runAsGroup=2000", "fsGroup=3000", "runAsNonRoot=false", "data-claim at /data (read-write)"} {
		if !strings.Contains(id, want) {
			t.Errorf("identity %q missing %q", id, want)
		}
	}
	if strings.Contains(id, "stat") {
		t.Errorf("identity must not claim on-disk ownership/mode: %q", id)
	}

	var sib string
	for _, s := range en.PVCSiblings {
		if strings.Contains(s, "app-xyz") {
			sib = s
		}
		if strings.Contains(s, "unrelated") {
			t.Errorf("unrelated claim must not be a sibling: %v", en.PVCSiblings)
		}
	}
	if sib == "" {
		t.Fatalf("expected app-xyz as a same-claim sibling, got %v", en.PVCSiblings)
	}
	if !strings.Contains(sib, "Running") || !strings.Contains(sib, "1/1 ready") {
		t.Errorf("sibling %q must carry phase and readiness", sib)
	}
	// The sibling must carry its own declared identity and mount so the
	// operator can compare it with the mover's on the same claim. Container
	// runAsUser overrides the pod; pod fsGroup/runAsNonRoot are inherited.
	for _, want := range []string{
		"container app (declared: runAsUser=2000 runAsGroup=unset fsGroup=3000 runAsNonRoot=true)",
		"data-claim at /data (read-only)",
	} {
		if !strings.Contains(sib, want) {
			t.Errorf("sibling %q missing %q", sib, want)
		}
	}
}

// A sibling with several containers must only report the container(s) that
// actually mount the matched claim, so the identity/mount detail does not
// imply the other containers touch the volume.
func TestEnrichSiblingDetailOnlyListsMountingContainers(t *testing.T) {
	ns1 := `{
		"items":[
			{"metadata":{"name":"mover","namespace":"ns1"},
			 "spec":{
				"containers":[{"name":"mover","volumeMounts":[{"name":"data","mountPath":"/data"}]}],
				"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]},
			 "status":{"phase":"Failed","containerStatuses":[
				{"name":"mover","ready":false,"state":{"terminated":{"exitCode":1,"reason":"Error"}}}]}},
			{"metadata":{"name":"app-xyz","namespace":"ns1"},
			 "spec":{
				"containers":[
					{"name":"app","securityContext":{"runAsUser":2000},
					 "volumeMounts":[{"name":"data","mountPath":"/data"}]},
					{"name":"sidecar"}],
				"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]},
			 "status":{"phase":"Running","containerStatuses":[
				{"name":"app","ready":true,"state":{"running":{}}},
				{"name":"sidecar","ready":true,"state":{"running":{}}}]}}
		]}`
	srv := identityHarness(t, map[string]string{"ns1": ns1})
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubePodCrashLooping", "namespace": "ns1", "pod": "mover",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	var sib string
	for _, s := range en.PVCSiblings {
		if strings.Contains(s, "app-xyz") {
			sib = s
		}
	}
	if sib == "" {
		t.Fatalf("expected app-xyz as a same-claim sibling, got %v", en.PVCSiblings)
	}
	if !strings.Contains(sib, "container app (declared: runAsUser=2000") {
		t.Errorf("sibling %q must describe the mounting container app", sib)
	}
	if strings.Contains(sib, "sidecar") {
		t.Errorf("sibling %q must not describe a container that does not mount the claim", sib)
	}
}

// A KubeJobFailed alert names a Job via job_name and carries no pod label
// (#127). The Job's owned failing Pod must still be enriched with its declared
// identity and same-claim siblings - the exact backup/mover incident this
// feature exists for.
func TestEnrichJobFailedPodIdentityAndSiblings(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"backup-0","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"backup","uid":"job-uid-1"}]},
			 "spec":{
				"containers":[{"name":"mover",
					"securityContext":{"runAsUser":4000,"runAsNonRoot":false},
					"volumeMounts":[{"name":"data","mountPath":"/data"}]}],
				"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]},
			 "status":{"phase":"Failed","containerStatuses":[
				{"name":"mover","ready":false,"restartCount":0,
				 "state":{"terminated":{"exitCode":1,"reason":"Error"}}}]}},
			{"metadata":{"name":"web-0","namespace":"ns1"},
			 "spec":{
				"securityContext":{"runAsGroup":4000},
				"containers":[{"name":"app",
					"securityContext":{"runAsUser":5000,"runAsNonRoot":false},
					"volumeMounts":[{"name":"data","mountPath":"/data","readOnly":false}]}],
				"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]},
			 "status":{"phase":"Running","containerStatuses":[
				{"name":"app","ready":true,"state":{"running":{}}}]}}
		]}`
	jobs := map[string]jobSpec{
		"backup": {json: `{"metadata":{"name":"backup","namespace":"ns1","uid":"job-uid-1"},
			"spec":{"template":{"metadata":{"labels":{"job-name":"backup"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	id, ok := en.PodID["ns1/backup-0"]
	if !ok {
		t.Fatalf("a Job-owned failing pod must carry identity evidence, got %v", en.PodID)
	}
	if !strings.Contains(id, "runAsUser=4000") || !strings.Contains(id, "data-claim at /data") {
		t.Errorf("job pod identity = %q, want declared identity and PVC mount", id)
	}
	var sib string
	for _, s := range en.PVCSiblings {
		if strings.Contains(s, "web-0") {
			sib = s
		}
	}
	if sib == "" {
		t.Fatalf("expected the same-claim sibling web-0 for the job pod, got %v", en.PVCSiblings)
	}
	for _, want := range []string{
		"container app (declared: runAsUser=5000 runAsGroup=4000 fsGroup=unset runAsNonRoot=false)",
		"data-claim at /data (read-write)",
	} {
		if !strings.Contains(sib, want) {
			t.Errorf("job sibling %q missing %q", sib, want)
		}
	}
}

// Claims are namespace-local: a pod in ns2 mounting a claim with the same name
// as the ns1 target's claim is not a same-claim sibling.
func TestEnrichSiblingsAreNamespaceScoped(t *testing.T) {
	ns1 := `{
		"items":[
			{"metadata":{"name":"mover","namespace":"ns1"},
			 "spec":{
				"containers":[{"name":"mover","volumeMounts":[{"name":"data","mountPath":"/data"}]}],
				"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"shared"}}]},
			 "status":{"phase":"Failed","containerStatuses":[
				{"name":"mover","ready":false,"state":{"terminated":{"exitCode":1,"reason":"Error"}}}]}},
			{"metadata":{"name":"ns1-peer","namespace":"ns1"},
			 "spec":{
				"containers":[{"name":"p","volumeMounts":[{"name":"data","mountPath":"/data"}]}],
				"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"shared"}}]},
			 "status":{"phase":"Running","containerStatuses":[
				{"name":"p","ready":true,"state":{"running":{}}}]}}
		]}`
	ns2 := `{
		"items":[
			{"metadata":{"name":"ns2-peer","namespace":"ns2"},
			 "spec":{
				"containers":[{"name":"p","volumeMounts":[{"name":"data","mountPath":"/data"}]}],
				"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"shared"}}]},
			 "status":{"phase":"Running","containerStatuses":[
				{"name":"p","ready":true,"state":{"running":{}}}]}}
		]}`
	srv := identityHarness(t, map[string]string{"ns1": ns1, "ns2": ns2})
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1", "ns2"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubePodCrashLooping", "namespace": "ns1", "pod": "mover",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)

	var ns1Peer, ns2Peer bool
	for _, s := range en.PVCSiblings {
		if strings.Contains(s, "ns1-peer") {
			ns1Peer = true
		}
		if strings.Contains(s, "ns2-peer") {
			ns2Peer = true
		}
	}
	if !ns1Peer {
		t.Errorf("expected the same-namespace sibling ns1-peer, got %v", en.PVCSiblings)
	}
	if ns2Peer {
		t.Errorf("a same-named claim in another namespace must not be a sibling: %v", en.PVCSiblings)
	}
}

// The sibling list is capped so a group spanning many pods does not become a
// namespace dump.
func TestEnrichSiblingCap(t *testing.T) {
	var items []string
	items = append(items, `{"metadata":{"name":"mover","namespace":"ns1"},
		"spec":{"containers":[{"name":"c","volumeMounts":[{"name":"data","mountPath":"/data"}]}],
		"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"shared"}}]},
		"status":{"phase":"Failed","containerStatuses":[{"name":"c","ready":false,"state":{"terminated":{"exitCode":1,"reason":"Error"}}}]}}`)
	for i := 0; i < 6; i++ {
		items = append(items, fmt.Sprintf(`{"metadata":{"name":"peer-%d","namespace":"ns1"},
			"spec":{"containers":[{"name":"c","volumeMounts":[{"name":"data","mountPath":"/data"}]}],
			"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"shared"}}]},
			"status":{"phase":"Running","containerStatuses":[{"name":"c","ready":true,"state":{"running":{}}}]}}`, i))
	}
	srv := identityHarness(t, map[string]string{"ns1": `{"items":[` + strings.Join(items, ",") + `]}`})
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubePodCrashLooping", "namespace": "ns1", "pod": "mover",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)
	if len(en.PVCSiblings) > sameClaimSibMax {
		t.Errorf("expected at most %d same-claim siblings, got %d: %v", sameClaimSibMax, len(en.PVCSiblings), en.PVCSiblings)
	}
}

// A failing target that declares nothing yields an explicit "unset" identity
// line rather than a guessed identity, and mounts nothing so it has no claim
// and no siblings.
func TestEnrichAllIdentityUnset(t *testing.T) {
	ns1 := `{
		"items":[
			{"metadata":{"name":"mover","namespace":"ns1"},
			 "status":{"phase":"Failed","containerStatuses":[
				{"name":"c","ready":false,"state":{"terminated":{"exitCode":1,"reason":"Error"}}}]}}
		]}`
	srv := identityHarness(t, map[string]string{"ns1": ns1})
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubePodCrashLooping", "namespace": "ns1", "pod": "mover",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)
	id, ok := en.PodID["ns1/mover"]
	if !ok {
		t.Fatalf("a failing target must carry an identity line, got %v", en.PodID)
	}
	for _, want := range []string{"runAsUser=unset", "runAsGroup=unset", "fsGroup=unset", "runAsNonRoot=unset"} {
		if !strings.Contains(id, want) {
			t.Errorf("expected %q in %q", want, id)
		}
	}
	if len(en.PVCSiblings) != 0 {
		t.Errorf("a target with no claim must have no siblings, got %v", en.PVCSiblings)
	}
}

// A healthy target the alert named has no failing container, so it carries no
// identity line: the section is about the failure, not the pod's existence.
func TestEnrichHealthyTargetNoIdentity(t *testing.T) {
	ns1 := `{
		"items":[
			{"metadata":{"name":"mover","namespace":"ns1"},
			 "spec":{"securityContext":{"runAsUser":1000}},
			 "status":{"phase":"Running","containerStatuses":[
				{"name":"c","ready":true,"state":{"running":{}}}]}}
		]}`
	srv := identityHarness(t, map[string]string{"ns1": ns1})
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubePodCrashLooping", "namespace": "ns1", "pod": "mover",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)
	if _, ok := en.PodID["ns1/mover"]; ok {
		t.Errorf("a healthy target with no failing container must not carry an identity line, got %v", en.PodID)
	}
}

// TestKubeGetCapsOverSizeResponse guards against the unbounded-body
// regression tracked in #210: an apiserver GET must fail rather than buffer a
// body larger than kubeBodyCap, matching the metrics and logs read paths.
func TestKubeGetCapsOverSizeResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("a", 64<<10)
		for i := 0; i < 96; i++ { // 6 MiB total, well over the 4 MiB cap
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, token: "tok", hc: http.DefaultClient}
	var out podList
	err := k.get(context.Background(), "/api/v1/namespaces/ns/pods", &out)
	if err == nil {
		t.Fatal("expected error for over-cap response, got nil")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error = %q, want substring %q", err.Error(), "exceeded")
	}
}

// TestKubeGetStillDecodesUnderCap pins the success path through the capped
// read: a normal pod list decodes exactly as it did before the cap landed.
func TestKubeGetStillDecodesUnderCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"items":[{"metadata":{"name":"p1","namespace":"ns1"},"status":{"phase":"Failed"}}]}`))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, token: "tok", hc: http.DefaultClient}
	var out podList
	if err := k.get(context.Background(), "/api/v1/namespaces/ns1/pods", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(out.Items) != 1 || out.Items[0].Metadata.Name != "p1" {
		t.Errorf("unexpected decode: %+v", out.Items)
	}
}
