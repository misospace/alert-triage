package main

import (
	"strings"
	"testing"
)

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
		// credential. The tail goes with the credential the word split
		// redacted, the rule the mid-word branch follows since #240.
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
	// Four payload families still reached the digest in plaintext (issue
	// #260): a credential behind a join the gate cannot read whole, a
	// credential behind a leading glue run, a credential in the value slot
	// of a "key=value" header, and a credential in front of a scheme word
	// the prose continues. None of them may survive, in any of the arms
	// that carry them.
	for _, in := range []string{
		"basic dXNlcjpwYXNz=-dXNlcjE6cA",
		"basic -dXNlcjpwYXNz",
		"authorization: key=dXVpZDpwYXNz-",
		"authorization: key=dXVpZDpwYXNzbasically",
		"authorization: dXVpZDpwYXNzbasicdXVpZDpwYXNz",
		// The scheme context: the scheme word's word chain swallows the
		// credential and the separator behind it as one token.
		"basic dXVpZDpwYXNz- in request",
		"basic dXVpZDpwYXNzbasically in request",
		"authorization: dXVpZDpwYXNzbasically.example.com",
	} {
		for _, p := range []string{"dXNlcjpwYXNz", "dXNlcjE6cA", "dXVpZDpwYXNz"} {
			if got := stripSecrets(in); strings.Contains(got, p) {
				t.Errorf("stripSecrets(%q) = %q; payload %q survived", in, got, p)
			}
		}
	}
	// A credential the decode gate cannot separate from the prose behind
	// it reached the digest whole (issue #263): the head decodes, the
	// residue behind it does not, so no whole-run or word-based arm fired.
	// The head must go in every arm that carries it — the bare-scheme
	// run, the header value and the "=" join segment.
	for _, in := range []string{
		"basic dXNlcjE6cAfoo",
		"basic dXNlcjE6cAxbasic",
		"basic dXNlcjpwYXNz_+xbasic",
		"authorization: key=dXNlcjE6cAxbasic",
		"authorization: dXNlcjpwYXNz_+xbasic",
		"authorization: key=dXNlcjpwYXNz_+xbasic",
		"authorization: dXNlcjE6cAfoo",
		"authorization: key=dXNlcjE6cAfoo",
		"basic auth dXNlcjE6cAfoo",
		"failed with basic dXNlcjE6cAfoo in request",
		`{"authorization": "key=dXNlcjE6cAxbasic"}`,
	} {
		for _, p := range []string{"dXNlcjE6cA", "dXNlcjpwYXNz"} {
			if got := stripSecrets(in); strings.Contains(got, p) {
				t.Errorf("stripSecrets(%q) = %q; payload %q survived", in, got, p)
			}
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

// TestStripSecretsBasicAuthJoinCutExposesMidWordGone pins that a #259 cut
// on one join part puts the whole join's remaining gate-failing segments in
// front of the mid-word judgement (#240 review): a cut can expose the
// join's credential only in a later part — leading glue hides it from the
// whole-part decode test — so judging the word-split during the first pass
// skipped the segment behind the cut and shipped its payload.
func TestStripSecretsBasicAuthJoinCutExposesMidWordGone(t *testing.T) {
	tests := []struct{ in, want string }{
		// Leading glue hides the first segment's credential from the
		// whole-part decode test: the glue-trim cut redacts it, and the
		// segment behind the cut — the reason the join holds a credential
		// at all — faces the mid-word judgement in the second sweep.
		{"basic +dXVpZDpwYXNz=basic-dXNlcjpwYXNz", "basic +[REDACTED]=basic-[REDACTED]"},
		{"authorization: +dXVpZDpwYXNz=basic-dXNlcjpwYXNz", "authorization: +[REDACTED]=basic-[REDACTED]"},
		// The "/" glue the same way.
		{"basic /dXVpZDpwYXNz=basic-dXNlcjpwYXNz", "basic /[REDACTED]=basic-[REDACTED]"},
		// The cut in the later part: the sweep still reaches the segment
		// before it, so the judgement does not depend on part order.
		{"authorization: basic-dXNlcjpwYXNz=+dXVpZDpwYXNz", "authorization: basic-[REDACTED]=+[REDACTED]"},
		// A word whose residue decodes to nothing is prose: the sweep runs,
		// the gate decides, nothing is redacted.
		{"authorization: -dXVpZDpwYXNz=basic-words", "authorization: -[REDACTED]=basic-words"},
	}
	for _, tt := range tests {
		if got := stripSecrets(tt.in); got != tt.want {
			t.Errorf("stripSecrets(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
	// The sweep re-emits glue and scheme words as context, so a second pass
	// must leave the output unchanged.
	for _, tt := range tests {
		once := stripSecrets(tt.in)
		if twice := stripSecrets(once); twice != once {
			t.Errorf("stripSecrets(%q) = %q; second pass = %q", tt.in, once, twice)
		}
	}
}

// TestStripSecretsBasicAuthMidWordUndecodableResidueGone pins the residue of
// a mid-run scheme word whose material behind it never decodes (issue #262):
// the occurrence was skipped then, so no segment around the word was judged
// and the credentials beside it stayed in plaintext. A residue that carries a
// credential plus one trailing character whose bits are left over
// ("…<credential>x") does not decode as a whole, but the longest decodable
// prefix of it is a credential all the same, so the payload goes. The scheme
// word stays readable as the context it is, the prose around it survives, and
// the output is stable under a second pass.
func TestStripSecretsBasicAuthMidWordUndecodableResidueGone(t *testing.T) {
	tests := []struct{ in, want string }{
		// A mid-run scheme word with a credential behind it that carries a
		// trailing character whose bits are left over: the payload behind
		// the word goes, the word stays as the context it is.
		{"basic dXNlcjpwYXNz-basicdXNlcjpwYXNzx", "basic [REDACTED]basic[REDACTED]x"},
		// The same shape in a header value, behind a join: the join's key
		// slot stays readable and the word splits the value.
		{"authorization: key=dXVpZDpwYXNz/basic-dXNlcjpwYXNzx", "authorization: key=[REDACTED]/basic-[REDACTED]x"},
		// The leftover character is any one the alphabet carries: the
		// credential behind the word goes whatever it is.
		{"basic dXNlcjpwYXNz-basicdXNlcjpwYXNza", "basic [REDACTED]basic[REDACTED]a"},
		// A residue that decodes as a whole is judged the way it always
		// was: both payloads go and the word stays.
		{"basic dXNlcjpwYXNz-basicdXNlcjpwYXNz", "basic [REDACTED]basic[REDACTED]"},
		// A word the prose continues is prose: nothing behind it holds a
		// credential, so no segment is judged and the text stays readable.
		{"basic dXNlcjpwYXNzbasically", "basic [REDACTED]basically"},
		{"authorization: dXVpZDpwYXNzbasically.example.com", "authorization: [REDACTED]basically.example.com"},
	}
	for _, tt := range tests {
		if got := stripSecrets(tt.in); got != tt.want {
			t.Errorf("stripSecrets(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
	// The judgements re-emit glue and words as context, so a second pass
	// must leave the output unchanged.
	for _, tt := range tests {
		once := stripSecrets(tt.in)
		if twice := stripSecrets(once); twice != once {
			t.Errorf("stripSecrets(%q) = %q; second pass = %q", tt.in, once, twice)
		}
	}
	// Whatever the residue carries, no credential payload may reach the
	// digest, in either context.
	for _, in := range []string{
		"basic dXNlcjpwYXNz-basicdXNlcjpwYXNzx",
		"basic dXNlcjpwYXNz-basicdXNlcjpwYXNza",
		"basic dXNlcjpwYXNz-basicdXNlcjpwYXNzx in request",
		"authorization: key=dXVpZDpwYXNz/basic-dXNlcjpwYXNzx",
		"authorization: dXVpZDpwYXNzbasicdXNlcjpwYXNzx",
		"basic Zm9vOmJhcg+basic-dXNlcjpwYXNzx",
		"basic dXNlcjpwYXNz/basic-dXNlcjpwYXNzx",
		// A scheme word in the middle of a run with a credential behind it
		// and another scheme word behind that: the credentials on either
		// side of the first word go, and the second word's context stays
		// readable.
		"basic cjpubbasicdXNlcjpwYXNz--authorizationx",
		"authorization: key=dXNlcjpwYXNz_basic_dXNlcjpwYXNz_Basicx",
		// A credential behind a scheme word whose residue carries a
		// credential of its own: the residue goes whole.
		"basic-cjpbasic.-Zm9vOmJhcg",
	} {
		got := stripSecrets(in)
		for _, p := range []string{"dXNlcjpwYXNz", "dXVpZDpwYXNz", "Zm9vOmJhcg"} {
			if strings.Contains(got, p) {
				t.Errorf("stripSecrets(%q) = %q; payload %q survived", in, got, p)
			}
		}
	}
	// The words that are prose stay prose: a word the prose continues, and
	// the words that merely carry it, are not credentials.
	for _, in := range []string{
		"subbasic",
		"offbasic",
		"basically",
		"basic subbasic",
		"basic offbasic",
		"basic subbasic in request",
		"basic offbasic in request",
	} {
		if got := stripSecrets(in); got != in {
			t.Errorf("stripSecrets(%q) = %q; prose changed", in, got)
		}
	}
	// A credential behind prose the word chain carries is still a
	// credential: the prose stays readable, the payload does not.
	for _, tt := range []struct{ in, want string }{
		{"basic subbasic dXNlcjpwYXNz", "basic subbasic [REDACTED]"},
		{"basic offbasic dXNlcjpwYXNz", "basic offbasic [REDACTED]"},
	} {
		if got := stripSecrets(tt.in); got != tt.want {
			t.Errorf("stripSecrets(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

// TestStripSecretsBasicAuthResidualFamiliesGone pins the four payload
// families that still reached the digest in plaintext (issue #260): a
// credential behind a join the gate cannot read whole, a credential behind a
// leading glue run, a credential in the value slot of a "key=value" header,
// and a credential in front of a scheme word the prose continues. The
// payload goes in every one of them, the join and the glue stay readable,
// and the output is stable under a second pass.
func TestStripSecretsBasicAuthResidualFamiliesGone(t *testing.T) {
	tests := []struct{ in, want string }{
		// A credential in the slot behind a join, with a glue run the gate
		// fails on: the payload goes, the join and the glue stay.
		{"basic dXNlcjpwYXNz=-dXNlcjE6cA", "basic [REDACTED]=-[REDACTED]"},
		// A credential behind a leading glue run: the glue stays where the
		// line carried it, the payload goes.
		{"basic -dXNlcjpwYXNz", "basic -[REDACTED]"},
		// A credential in the value slot of a "key=value" header, with the
		// glue behind it: the payload and the trailing glue go, the key and
		// the join stay.
		{"authorization: key=dXVpZDpwYXNz-", "authorization: key=[REDACTED]"},
		// A credential in front of a scheme word the prose continues: the
		// word is prose, not a scheme word, so the payload goes and the word
		// stays readable.
		{"authorization: key=dXVpZDpwYXNzbasically", "authorization: key=[REDACTED]basically"},
		// A scheme word glued between two credentials is a scheme word: both
		// payloads go and the word stays as the context they were read with.
		{"authorization: dXVpZDpwYXNzbasicdXVpZDpwYXNz", "authorization: [REDACTED]basic[REDACTED]"},
		// The same families in the scheme context: the scheme word's word
		// chain swallows the credential and the separator behind it as one
		// token, so the shared judge has to reach that arm too.
		{"basic dXVpZDpwYXNz- in request", "basic [REDACTED] in request"},
		{"basic dXVpZDpwYXNzbasically in request", "basic [REDACTED]basically in request"},
		// The tail follows the prose the payload sits in front of, not the
		// payload, so it stays visible: the operator still sees the host the
		// line named.
		{"authorization: dXVpZDpwYXNzbasically.example.com", "authorization: [REDACTED]basically.example.com"},
	}
	for _, tt := range tests {
		if got := stripSecrets(tt.in); got != tt.want {
			t.Errorf("stripSecrets(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
	// The judgements re-emit glue and words as context, so a second pass
	// must leave the output unchanged.
	for _, tt := range tests {
		once := stripSecrets(tt.in)
		if twice := stripSecrets(once); twice != once {
			t.Errorf("stripSecrets(%q) = %q; second pass = %q", tt.in, once, twice)
		}
	}
}

// TestStripSecretsBasicAuthCredentialBeforeResidueGone pins the shapes
// issue #263 reproduces: a credential the decode gate cannot separate from
// the prose behind it — the head decodes, the residue does not, so no
// whole-run or word-based arm fired and the payload reached the digest
// whole. The longest prefix that decodes is redacted and what decodes to
// nothing behind it is re-emitted, in the bare-scheme run, the header value
// and the "=" join segment alike. Prose the gate refuses stays
// byte-identical: the gate, not the shape, decides. Where the payload's
// letters extend into the word behind it and the extension still decodes,
// the cut cannot tell them apart and takes the longest — the trade-off the
// "dXNlcjpwYXNzprose" pin owns below.
func TestStripSecretsBasicAuthCredentialBeforeResidueGone(t *testing.T) {
	tests := []struct{ in, want string }{
		// The bare-scheme run: the residue is prose and stays readable.
		{"basic dXNlcjE6cAfoo", "basic [REDACTED]foo"},
		// The residue ends on a scheme word the payload's leftover bits
		// glue a letter onto: the word is residue here, not a scheme word,
		// and the payload goes with it readable.
		{"basic dXNlcjE6cAxbasic", "basic [REDACTED]xbasic"},
		// The payload whole with glue behind it the gate cannot read
		// across ("_" and "+" mix the alphabets): the residue keeps the
		// glue it carried.
		{"basic dXNlcjpwYXNz_+xbasic", "basic [REDACTED]_+xbasic"},
		// The header value and the "=" join segment: the shared judge
		// reaches both, the key and the join stay readable.
		{"authorization: key=dXNlcjE6cAxbasic", "authorization: key=[REDACTED]xbasic"},
		{"authorization: dXNlcjpwYXNz_+xbasic", "authorization: [REDACTED]_+xbasic"},
		{"authorization: key=dXNlcjpwYXNz_+xbasic", "authorization: key=[REDACTED]_+xbasic"},
		{"authorization: dXNlcjE6cAfoo", "authorization: [REDACTED]foo"},
		{"authorization: key=dXNlcjE6cAfoo", "authorization: key=[REDACTED]foo"},
		// A word chain in front of the core, and a dotted tail behind it:
		// the tail follows the residue's prose, not the payload.
		{"basic auth dXNlcjE6cAfoo", "basic auth [REDACTED]foo"},
		{"basic dXNlcjE6cAfoo.more", "basic [REDACTED]foo.more"},
		// The residue a second credential decodes in goes with the first:
		// re-emitting it would strand the payload behind "[REDACTED]"'s
		// brackets, where no later pass can read it back.
		{"basic dXNlcjE6cAdXNlcjE6cA", "basic [REDACTED]"},
		{"authorization: key=dXNlcjE6cAdXNlcjE6cA", "authorization: key=[REDACTED]"},
		// A residue split by a separator loses the pieces that decode and
		// keeps the prose between them; a piece that only starts with a
		// credential loses the credential the same way the segment does
		// (#263 one piece down, judged in the tail the separator leaves).
		{"basic dXNlcjE6cAfoo.dXNlcjpwYXNz", "basic [REDACTED]foo.[REDACTED]"},
		{"basic dXNlcjE6cAfoo.dXNlcjE6cAbar.dXNlcjpwYXNz", "basic [REDACTED]foo.[REDACTED]bar.[REDACTED]"},
		{"authorization: dXNlcjE6cAfoo.dXNlcjE6cAbar", "authorization: [REDACTED]foo.[REDACTED]bar"},
		{"authorization: key=dXNlcjE6cAfoo.dXNlcjE6cAbar", "authorization: key=[REDACTED]foo.[REDACTED]bar"},
		// An extension of the payload by the word behind it can decode too
		// — a password byte may be anything above the control range — and
		// the cut cannot tell that extension apart from a longer
		// credential, so it takes the longest and the word loses its head
		// letters. The trade-off is the one #217 accepted at piece
		// granularity, paid in prose directly behind a live payload.
		{"basic dXNlcjpwYXNzprose", "basic [REDACTED]e"},
		// The JSON-quoted shape, which is how the header reaches a log in
		// practice.
		{`{"authorization": "key=dXNlcjE6cAxbasic"}`, `{"authorization": "key=[REDACTED]xbasic"}`},
		// Prose stays byte-identical.
		{"basic credentials expire", "basic credentials expire"},
		{"authorization: key=authentication", "authorization: key=authentication"},
	}
	for _, tt := range tests {
		if got := stripSecrets(tt.in); got != tt.want {
			t.Errorf("stripSecrets(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
	// The judge re-emits the residue it refused, so a second pass must
	// leave the output unchanged.
	for _, tt := range tests {
		once := stripSecrets(tt.in)
		if twice := stripSecrets(once); twice != once {
			t.Errorf("stripSecrets(%q) = %q; second pass = %q", tt.in, once, twice)
		}
	}
	// Whatever the residue reads like, no credential payload may reach
	// the digest.
	for _, in := range []string{
		"basic dXNlcjE6cAfoo",
		"basic dXNlcjE6cAxbasic",
		"basic dXNlcjpwYXNz_+xbasic",
		"authorization: key=dXNlcjE6cAxbasic",
		"authorization: dXNlcjpwYXNz_+xbasic",
		"authorization: key=dXNlcjpwYXNz_+xbasic",
		`{"authorization": "key=dXNlcjE6cAxbasic"}`,
	} {
		for _, p := range []string{"dXNlcjE6cA", "dXNlcjpwYXNz"} {
			if got := stripSecrets(in); strings.Contains(got, p) {
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
		// A credential the gate cannot separate from the prose behind it
		// (issue #263): the cut re-emits what decodes to nothing, so the
		// second pass must not grow it.
		"basic dXNlcjE6cAfoo",
		"basic dXNlcjE6cAxbasic",
		"basic dXNlcjpwYXNz_+xbasic",
		"authorization: key=dXNlcjE6cAxbasic",
		// A residue a second credential decodes in is swallowed whole, and
		// a separator-split residue loses its decodable pieces: neither
		// re-emit may grow on a second pass.
		"basic dXNlcjE6cAdXNlcjE6cA",
		"basic dXNlcjE6cAfoo.dXNlcjpwYXNz",
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
