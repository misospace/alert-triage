package main

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"
)

// secretPatterns are common patterns that likely contain secrets in logs.
// Each entry carries its own replacement template and an optional guard.
// Most consume the whole match; RE2 has no lookbehind, so a pattern that
// must keep a leading key visible for the operator captures it instead and
// re-emits it in repl. A non-nil guard vetoes individual matches of its
// pattern (stripSecrets falls back to per-match filtering for those).
var secretPatterns = []struct {
	re    *regexp.Regexp
	repl  string
	guard func(match string) bool
}{
	// JSON/structured logs quote the key — {"password": "hunter2"} — which
	// the bare keyword[=:] forms below cannot reach, so this runs first and
	// owns that shape. Real-world keys are usually prefixed ("access_token",
	// "client_secret", "db_password"), so the captured key may carry a
	// prefix segment ending in "_" or "-" and is re-emitted intact. That
	// also over-redacts innocent keys like "note_password"; fail-safe beats
	// leak. The value must be quoted; a bare word after the key is prose,
	// not a secret. Escaped quotes inside the value are consumed too,
	// otherwise a value containing \" leaves a half-redacted remnant.
	{
		regexp.MustCompile(`(?i)"((?:[a-z0-9_.\-]+[_\-])?(?:password|passwd|pwd|token|bearer|secret|credential|api[_\-]?key|aws_access_key_id|aws_secret_access_key))"(\s*:\s*)"(?:[^"\\]|\\.)*"`),
		`"$1"$2"[REDACTED]"`,
		nil,
	},
	{regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+`), "[REDACTED]", nil},
	{regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*\S+`), "[REDACTED]", nil},
	{regexp.MustCompile(`(?i)(token|bearer)\s*[=:]\s*\S+`), "[REDACTED]", nil},
	{regexp.MustCompile(`(?i)(secret|credential)\s*[=:]\s*\S+`), "[REDACTED]", nil},
	{regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*\S+`), "[REDACTED]", nil},
	// Authorization header lines separate "Bearer" from the token with a
	// space, which the keyword[=:] forms above cannot match. The token is
	// consumed but the "authorization:" name stays so operators can see
	// what was stripped. Percent-encoding (%3D padding and the like) is
	// part of the token class so it cannot leave a remnant after the
	// match. The floor is eight characters: short enough that digit- or
	// separator-bearing credentials are caught, while lone short words
	// ("bearer 401") are untouched. The guard then rejects what is
	// certainly not a credential: runs of letters and hyphens that reach
	// beyond the hex alphabet ("token-expiry-validation-failed-check-logs"
	// is a message, not a credential, and redacting it would delete
	// evidence). Hex runs are the exception — "deadbeefdeadbeef" is all
	// letters but is token material, so it is redacted even though no
	// digit or separator appears. The accepted residual under-redaction is
	// a letters-and-hyphens run that is not pure hex, e.g. "Bearer
	// mysecretpassword" or the hyphenated hex "Bearer dead-beef-cafe-babe";
	// leaking that is rarer in real logs than the evidence loss full
	// redaction would cause. The floor conversely over-redacts values that
	// are not credentials: a timestamp, IP address or version string
	// directly after "bearer" goes too.
	{
		regexp.MustCompile(`(?i)bearer\s+[a-z0-9\-._~+/=%]{8,}=*`),
		"[REDACTED]",
		func(match string) bool {
			// The match is "bearer" + a whitespace run + the token; only
			// the token part is judged.
			token := match
			if i := strings.IndexAny(match, " \t\n\v\f\r"); i >= 0 {
				token = strings.TrimLeft(match[i+1:], " \t\n\v\f\r")
			}
			return isHexRun(token) || strings.ContainsAny(token, "0123456789._~+/=%")
		},
	},
}

// isHexRun reports whether s consists only of hexadecimal digits. Hex
// credentials need not contain a digit: an all-letter run such as
// "deadbeefdeadbeef" reads like prose to a letters-and-hyphens veto but is
// token material, while ordinary prose almost always uses letters outside
// [a-fA-F].
func isHexRun(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// pctEncodedSeparator matches the percent-encoded forms of the separators
// the Basic-scheme interstitial accepts — space, colon, equals — because
// URL- and query-encoded auth values logged by proxies and web apps arrive
// with the scheme word glued to the credential ("Basic%20<credential>").
// It is spliced into patterns compiled with (?i), so both hex cases match.
const pctEncodedSeparator = `(?:%20|%3a|%3d)+`

// schemeWordLeftBoundary matches what may precede the Basic scheme word: the
// start of the text, a non-letter, or a percent-encoded token. A word
// boundary is the wrong rule there. A percent-encoded separator ends in a hex
// digit ("%3Dbasic") and a digit can abut the scheme word ("0basic"), so \b
// never fired on either shape and the credential behind the scheme word
// survived. A letter still disqualifies the scheme word ("subbasic" is
// prose), which is what the word boundary was there for.
// The start-of-text alternative is what a scan that resumes mid-line sees:
// the resume point follows a separator, so it is a valid left boundary even
// when the character before it is a letter (the hex digit of a
// percent-encoded separator).
const schemeWordLeftBoundary = `(?:^|[^A-Za-z]|%[0-9A-Fa-f]{2})`

// basicAuthHeaderPattern matches an Authorization-style header and the
// credential it carries. The credential is base64("user-id:password")
// (RFC 7617) and has no keyword[=:] shape, so no entry in secretPatterns can
// reach it. The value is captured in the base64 alphabet, so the credential
// is separated from whatever follows it in the same token. The header name
// is captured and re-emitted so the operator can still see what was
// stripped, which is why this needs a replacement template instead of the
// slice's fixed "[REDACTED]".
//
// A strict base64 class stops at "." and "%", which left a JWT's later
// segments or a percent-encoded fragment sitting right next to
// "[REDACTED]". The optional tail consumes a glued "." or "%" and the token
// characters that follow, but only when redaction fires and only up to a
// token character, so a sentence-final "." after a credential survives. The
// decode test sees the core only, because the tail is not base64.
//
// The separator between the header name and the value may be missing: a log
// line that lost its colon still names the header, and the emitted tail of a
// credential chain ("<cred>.authorization <cred>") is such a line. Without
// it the chain's second credential kept its plaintext, because the tail
// says which scheme the value belongs to but the header pass could not read
// it back. The value still has to decode to a credential in that form, so
// prose around the header word survives; a header that kept its separator
// may also be redacted on the scheme word alone.
var basicAuthHeaderPattern = regexp.MustCompile(`(?i)((?:proxy-)?authorization"?\s*(?:[:=]\s*)?\s*"?)\s*((basic)(?:\s+|` + pctEncodedSeparator + `))?([A-Za-z0-9+/=_-]+)([.%][A-Za-z0-9+/=_.%-]*[A-Za-z0-9+/_-])?`)

// basicAuthSchemePattern finds a Basic-scheme credential that no header name
// basicAuthSchemePattern finds a Basic-scheme credential that no header name
// introduces. The interlude between the scheme and the credential — the
// separators (group 1) plus the tolerated words ("basic auth: <payload>",
// group 2) — is captured so every credential-shaped run in the word chain can
// face the decode gate itself, judged leftmost first: the leftmost run sits
// right after the scheme separators, so the strict form "basic <credential>"
// is tested before any word further back. That ordering is what issue #224
// needed. The greedy word group used to swallow the credential itself —
// "basic dXNlcjpwYXNz in request" — and judge the word behind it, which left
// the credential in plaintext. Prose still survives, because words like "auth
// failed for" never decode to a user:password pair, and a redacted run
// carries no base64 material, so the fixed-point loop in stripBasicAuth still
// converges. The leading separators are captured apart from the word chain,
// and only the chain is split into judged runs: percent-encoded separators
// carry digits ("%20"), and splitting across them would glue "20" onto the
// leftmost credential — "basic%20dXNlcjpwYXNz in request" — and break its
// decode, while a word chain can never hold separator residue because its
// words are letters and hyphens. The separators between the tolerated words
// do not come in percent-encoded forms, because there the greedy word group
// would eat a real credential's "%3D" padding as a separator. The core
// (group 3) is the base64 alphabet; a glued "." or "%" tail (group 4) is
// consumed too, for the same reason as in the header pattern — a strict
// base64 class stops at those and left JWT segments and percent-encoded
// fragments next to "[REDACTED]". The tail ends on a token character, so
// sentence punctuation after a credential survives, and the decode test sees
// the core only. The scheme word starts on the left boundary above, which
// admits the percent-encoded and digit-glued shapes a word boundary rejected.
var basicAuthSchemePattern = regexp.MustCompile(`(?i)` + schemeWordLeftBoundary + `basic\b((?:[\s:=]|` + pctEncodedSeparator + `)*)((?:[A-Za-z][A-Za-z-]*[\s:=]+)*)([A-Za-z0-9+/=_-]+)([.%][A-Za-z0-9+/=_.%-]*[A-Za-z0-9+/_-])?`)

// basicAuthCredentialRun splits the word-chain part of the interlude into
// credential-shaped runs so each one can face the decode gate itself. The
// class omits "=": there it is a separator the word group placed between
// runs, not credential padding, so a run must stop at it. Keeping it in the
// class glued a credential to that separator, and on the next fixed-point
// pass the run decoded via the raw-base64 trim and the redaction swallowed
// the separator, dropping a "key=value" join (issue #224).
var basicAuthCredentialRun = regexp.MustCompile(`[A-Za-z0-9+/_-]+`)

// tailEndsInSchemeWord reports a tail that stops on a scheme or header word
// ("core.basic <cred>"): a pass cannot rescan what it emitted, so
// consuming that tail strips the NEXT credential's context and it survives.
// Emitting the tail instead lets the fixed-point pass below redact it.
// The glue counts in its percent-encoded form as well: a percent-encoded
// separator ends in a hex digit ("core%3Dbasic"), which the literal glue
// alone did not recognise, so the tail was consumed and the credential
// behind it kept its plaintext. The token arm must accept ANY percent token,
// not just the encoded separators, because the two rules read the same word:
// schemeWordLeftBoundary recognises a scheme word after any percent token,
// so a tail ending in a word behind an unenumerated one ("%3fbasic", the
// encoding of "?") is context the next pass will honour, and consuming it
// orphans the credential behind that word just as the literal glue did.
// The scheme word has to start where the scheme pass looks for one — after a
// non-letter, or after a percent-encoded token — so a word glued to letters
// is not a scheme word ("core.subbasic"). The match starts at the glue,
// which is the context the next pass reads the credential with.
var tailEndsInSchemeWord = regexp.MustCompile(`(?i)(?:(?:%[0-9A-Fa-f]{2})+[^A-Za-z]?|[^A-Za-z])(?:basic|authorization)$`)

// embeddedSchemeWord is a scheme word found inside a credential run rather
// than before it. The base64 alphabet admits "+", "/", "_", "-" and digits,
// so a scheme word can be glued to a credential with no separator, and the
// word's letters decode along with the credential. A run that passes the
// decode gate may therefore carry a scheme word inside it; that word is the
// context the credential behind it needs, so it is cut out and re-emitted.
var embeddedSchemeWord = regexp.MustCompile(`(?i)basic|authorization`)

// credentialAlphabets are the two base64 alphabets a client may have used
// to encode a credential. The char strings drive the clean-head scan in
// credentialRunBoundary; the decoders are the raw (unpadded) forms, whose
// byte stream a padded decode shares — padding only terminates the input,
// it changes no byte. The boundary takes the longest prefix over both, so
// their order here carries no weight.
var credentialAlphabets = []struct {
	chars  string
	decode *base64.Encoding
}{
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", base64.RawStdEncoding},
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", base64.RawURLEncoding},
}

// safeTail returns a captured tail that is safe to re-emit (issue #217). A
// tail that stops on a scheme word is emitted rather than consumed, because
// consuming it strips the next credential's context and the credential
// survives; the trailing scheme word therefore stays, since it is the
// context the next credential needs.
// Material ahead of that scheme word is redacted WHOLESALE, not selectively:
// inside a tail a credential cannot be told apart from a file name, a version
// string or a pod name, so picking out the segments that look like
// credentials would leak the ones that do not. The cost is that this deletes
// operator-visible evidence the previous code kept — a version string or a
// pod name inside a tail is gone with the credential.
// A tail that does not stop on a scheme word carries material too, so it is
// redacted whole; the callers consume such a tail rather than emit it, which
// makes that arm defensive.
func safeTail(tail string) string {
	loc := tailEndsInSchemeWord.FindStringIndex(tail)
	if loc == nil {
		return "[REDACTED]"
	}
	if loc[0] == 0 {
		return tail
	}
	interior := tail[:loc[0]]
	if interior[0] == '.' || interior[0] == '%' {
		return interior[:1] + "[REDACTED]" + tail[loc[0]:]
	}
	return "[REDACTED]" + tail[loc[0]:]
}

// gluedSchemeWordSuffix matches a run that ends on a scheme or header word,
// the shape splitGluedSchemeWord cuts. The word list must stay in step with
// tailEndsInSchemeWord, which reads the same words at a tail's end.
var gluedSchemeWordSuffix = regexp.MustCompile(`(?i)(?:basic|authorization)$`)

// schemeGlue is the glue a credential can carry before or after a scheme
// word it is glued to: the pattern padding and word-chain separators
// "=_-", plus "+" and "/" — base64 alphabet chars, which is why they are
// in every credential class, so they glue a credential to a following
// scheme word the same way a separator does and part the credential from
// its context the same way (issue #240).
const schemeGlue = `=_-+/`

// splitGluedSchemeWord cuts a credential-alphabet run into a credential and
// a scheme or header word glued to its end ("dXVpZDpwYXNzbasic",
// "dXVpZDpwYXNz=basic"), returning the index where the word starts. The core
// class of both Basic patterns stops at "." but not at "=", "_" or a letter,
// so the word is swallowed into the core, the decode gate fails on the
// combined run, and the credential survived next to the word (issue #227).
// The decode test strips schemeGlue from the candidate head first: padding
// and glue behind the payload mask its decode otherwise, so "+"/"/" and
// "=" glued between credential and word must come off before the gate is
// asked (issue #240). The trim only serves the test; whether the glue
// between the credential and the word survives is the call site's
// judgement below.
// Callers redact the decodable part before the index; the word is kept,
// because "[REDACTED]" ends on a non-letter, the boundary
// schemeWordLeftBoundary requires, so the next pass still reads the word as
// the context of whatever follows it. Whether the glue between the
// credential and the word survives is the call site's judgement: the judged
// word chain drops it with the redaction, the core and header arms keep
// the "=_-" glue they trim back off ("=", the join the line carried, and
// "_" and "-" the word-chain separators) and drop the "+"/"/" glue with
// the credential, base64 alphabet chars that nothing later can read.
// Words are cut
// from the right one at a time so a chain of glued words
// ("cred basicbasic") cuts at the leftmost word behind which the remainder
// still decodes. A run that is only scheme words never cuts: there is no
// credential ahead of the word, and prose ("subbasic", the word chain's own
// "basic") must survive the gate.
func splitGluedSchemeWord(run string) (int, bool) {
	end := len(run)
	for {
		loc := gluedSchemeWordSuffix.FindStringIndex(run[:end])
		if loc == nil || loc[0] == 0 {
			return 0, false
		}
		// The "+"/"/" glue must come off to let a "+/-glued" credential
		// decode (#240), but a trim that is too wide can push a
		// non-canonical tail (zero-leftover-bits padding the real
		// encoder emits anyway) out of the gate's accepted lengths, so
		// the trim the padding set alone gives ("=_-") is trusted too:
		// the cut fires when either head decodes.
		if decodesToBasicCredential(strings.TrimRight(run[:loc[0]], schemeGlue)) ||
			decodesToBasicCredential(strings.TrimRight(run[:loc[0]], "=_-")) {
			return loc[0], true
		}
		end = loc[0]
	}
}

// cutGluedSchemeWord splits a gate-passing credential run at a scheme word
// glued inside it, so the word survives as the context the credential behind
// it needs. Wholesale redaction would swallow the word with the run and
// orphan that credential.
//
// The head before the word must itself decode to a credential: that is what
// separates "dXVpZDpwYXNz+basic" (head "dXVpZDpwYXNz" is "uuid:pass") from
// prose ("subbasic": head "sub" decodes to nothing), and it keeps a word that
// merely shares a prefix with a scheme word out of the cut. Glue around the
// word is base64-alphabet glue ("+/_-="), not a separator the next pass can
// read, so it is trimmed: the glue before the head is tested away, the glue
// after the word is consumed, and the word is re-emitted with a real space.
// A word followed by a letter is not a scheme word ("dXVpZDpwYXNzbasically"),
// so that occurrence is skipped and the run keeps its wholesale redaction.
// The remainder behind the word must itself decode to a credential: a
// remainder that does not decode can never earn redaction behind the
// re-emitted word, so cutting there would ship it in plaintext and the run
// keeps its wholesale redaction instead.
func cutGluedSchemeWord(run string) (word, rest string, ok bool) {
	for _, m := range embeddedSchemeWord.FindAllStringIndex(run, -1) {
		if m[1] < len(run) {
			c := run[m[1]]
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				continue
			}
		}
		head := strings.TrimRight(run[:m[0]], "+/=-_")
		if head == "" || !decodesToBasicCredential(head) {
			continue
		}
		remainder := strings.TrimLeft(run[m[1]:], "+/=-_")
		if remainder != "" && !decodesToBasicCredential(remainder) {
			continue
		}
		return run[m[0]:m[1]], remainder, true
	}
	return "", "", false
}

// redactGluedWordSegments judges a run around a scheme word it carries in
// its middle (issue #240): every segment flanking an occurrence faces the
// decode gate on its own, with the glue on the segment's edge trimmed off
// because padding glued to the payload would mask its decode otherwise. A
// segment that decodes to a user:password pair is redacted; its leading
// glue stays visible because it is the separator the neighboring word hung
// on, and its payload and trailing glue go with it. The words stay: they
// are the context the next pass reads, and "[REDACTED]" ends on a
// non-letter, so later scans still read them as scheme words. A segment
// that is no credential is returned untouched, so the gate — not the
// word — decides, exactly as in splitGluedSchemeWord. Reports false when
// no segment decodes, and the caller then leaves the run in play.
func redactGluedWordSegments(run string) (string, bool) {
	locs := embeddedSchemeWord.FindAllStringIndex(run, -1)
	if locs == nil {
		return run, false
	}
	var out strings.Builder
	changed := false
	prev := 0
	for _, l := range locs {
		// A word followed by a letter is not a scheme word
		// ("authorizations", "basically"), unless the material behind it
		// is credential material: an undecodable residue would orphan
		// the credential inside it — the never-decodable-again shape
		// #217 guards the tail against — so the occurrence is skipped
		// when the residue behind it holds no credential, and no segment
		// around it is judged; the run keeps whatever its caller does
		// with undecodable runs.
		//
		// The skip must not hide a credential that sits behind the word
		// (issue #262): a residue that carries a credential plus one
		// trailing character whose bits are left over ("…<cred>x") does
		// not decode as a whole, so the whole-decode test alone skipped
		// the occurrence and left that credential in play; the prefix
		// test of segmentHoldsCredential is what sees it.
		if l[1] < len(run) {
			c := run[l[1]]
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				if !segmentHoldsCredential(run[l[1]:]) {
					continue
				}
			}
		}
		if l[0] > prev {
			if _, found := emitGluedWordSegment(&out, run[prev:l[0]]); found {
				changed = true
			}
		}
		out.WriteString(run[l[0]:l[1]])
		prev = l[1]
	}
	if prev < len(run) {
		if _, found := emitGluedWordSegment(&out, run[prev:]); found {
			changed = true
		}
	}
	if !changed {
		return run, false
	}
	return out.String(), true
}

// emitGluedWordSegment writes seg, judging it by the decode gate with the
// glue on its edge trimmed off. A segment that decodes redacts its payload
// and trailing glue and keeps the leading glue visible; anything else is
// written verbatim — unless the trimmed segment still carries an "=" join
// (issue #240, join review): "key=<credential>_<word>" reaches this arm
// undecoded whole, so every join face of the trimmed segment is judged
// like redactJoinSegments judges a core, with the segment's own glue
// written outside the judged part. A segment that is no credential as a
// whole but starts with one loses that credential (issue #262): a payload
// with one trailing character whose bits are left over ("…<cred>x") does
// not decode as a whole, and the payload behind the leftover character
// would otherwise ship in plaintext.
//
// It reports two things. "redacted" says whether the segment changed at
// all. "found" says whether the segment held a credential of its own: the
// mid-word judgement counts that as its own finding and acts on it, while a
// segment the shared judge answers on its own (a credential in front of a
// scheme word the prose continues) is left to that judge, which keeps the
// prose behind it readable and the tail that follows it visible
// (issue #262).
func emitGluedWordSegment(out *strings.Builder, seg string) (redacted, found bool) {
	lead := seg[:len(seg)-len(strings.TrimLeft(seg, schemeGlue))]
	trimmed := strings.Trim(seg, schemeGlue)
	if trimmed == "" {
		// The segment is pure glue: nothing to judge, glue passes (an
		// all-glue segment must not mint a redaction — "[REDACTED]"
		// emitted beyond the word would grow every pass).
		out.WriteString(seg)
		return false, false
	}
	if !decodesToBasicCredential(trimmed) {
		// The same trim-width worry splitGluedSchemeWord's gate answers:
		// a "+"/"/"-trailing payload head can decode with only the
		// "=_-" glue off, and then it is a credential just as much.
		alt := strings.Trim(seg, "=_-")
		if alt != "" && decodesToBasicCredential(alt) {
			out.WriteString(lead + "[REDACTED]")
			return true, true
		}
		if joined, ok := redactJoinSegments(trimmed); ok {
			trail := seg[len(strings.TrimRight(seg, schemeGlue)):]
			out.WriteString(lead + joined + trail)
			return true, true
		}
		if cut, ok := cutCredentialBeforeProse(seg); ok {
			// A credential in front of a scheme word the prose continues:
			// the word is prose, not a scheme word, so the credential goes
			// and the word and the prose behind it stay readable. The
			// shared judge answers the same shape one level down, and this
			// arm must not be weaker than it (issue #262: the mid-word
			// judgement fires on more segments now, so a segment it judges
			// has to lose every credential the shared judge would lose).
			out.WriteString(lead + cut)
			return true, false
		}
		if cut, ok := cutCredentialBeforeResidue(trimmed); ok {
			// The segment is no credential as a whole, but it starts
			// with one: the longest prefix that decodes to a
			// user:password pair is the credential, and the residue
			// behind it is judged rather than trusted — a residue
			// that is a credential of its own goes whole, so no
			// credential is stranded behind the redaction's brackets.
			// The segment's trailing glue stays: it is the separator
			// the neighbouring scheme word hung on, and dropping it
			// would leave that word unreadable as a scheme word and
			// the credential behind it unreadable to every later pass
			// (#217, issue #262).
			trail := seg[len(strings.TrimRight(seg, schemeGlue)):]
			out.WriteString(lead + cut + trail)
			return true, true
		}
		out.WriteString(seg)
		return false, false
	}
	out.WriteString(lead + "[REDACTED]")
	return true, true
}

// segmentHoldsCredential reports whether seg carries credential material the
// gate can point at: the segment decodes to a user:password pair as a whole,
// with the glue on its edges trimmed off, or its longest decodable prefix is
// such a pair.
//
// The prefix test is the one that sees a payload with one trailing character
// whose bits are left over ("…<cred>x"): such a segment does not decode as a
// whole, so the whole-decode test alone called it prose, and the credential
// behind the leftover character was neither redacted nor counted as a
// credential (issue #262). The gate — not the shape of the segment — still
// decides: the prefix decodes to a user:password pair, exactly as a whole
// segment has to.
func segmentHoldsCredential(seg string) bool {
	if decodesToBasicCredential(strings.Trim(seg, schemeGlue)) ||
		decodesToBasicCredential(strings.Trim(seg, "=_-")) {
		return true
	}
	_, ok := credentialRunBoundary(strings.Trim(seg, schemeGlue))
	return ok
}

// judgeSingleSegment judges one segment of a run that the decode gate
// declined, and reports the judged segment together with whether anything
// was redacted. The segment's leading glue stays where the line carried it
// — it is the separator the neighbouring token hung on — while its payload
// and its trailing glue go with the redaction: the glue behind a payload is
// base64-alphabet residue nothing later can read.
//
// A segment that carries a scheme word is judged around the word, not
// through it: the word is the context a credential behind it is read with,
// so it is cut out and re-emitted with a real space rather than swallowed
// with the redaction (#242). A credential that sits in front of a word the
// prose continues is the other way round — there the word is prose, not a
// scheme word, and the credential in front of it is unreachable to every
// later pass — so the head is redacted and the word stays readable. A
// payload head in front of a residue that carries no scheme word at all is
// the same shape without the word (#263): the longest prefix that decodes
// is redacted and what decodes to nothing behind it stays readable.
//
// The segment that carries an "=" is refused: a join is the join judge's
// business, and a segment that holds one is two segments of it.
func judgeSingleSegment(seg string) (string, bool) {
	if strings.Contains(seg, "=") {
		return seg, false
	}
	lead := seg[:len(seg)-len(strings.TrimLeft(seg, schemeGlue))]
	trimmed := strings.Trim(seg, schemeGlue)
	if trimmed == "" {
		// The segment is pure glue: nothing to judge, and a redaction
		// minted here would grow every pass.
		return seg, false
	}
	if decodesToBasicCredential(trimmed) {
		if word, rest, ok := cutGluedSchemeWord(trimmed); ok {
			out := lead + "[REDACTED] " + word
			if rest != "" {
				out += " " + rest
			}
			return out, true
		}
		return lead + "[REDACTED]", true
	}
	if alt := strings.Trim(seg, "=_-"); alt != "" && decodesToBasicCredential(alt) {
		// The same trim-width worry the other gates answer: a payload
		// whose decode only the "=_-" glue lets through is a credential
		// just as much (#240).
		return lead + "[REDACTED]", true
	}
	if out, ok := cutCredentialBeforeProse(seg); ok {
		return lead + out, true
	}
	if out, ok := cutCredentialBeforeResidue(trimmed); ok {
		return lead + out, true
	}
	return seg, false
}

// cutCredentialBeforeResidue redacts the credential a segment's payload
// starts with when everything behind it decodes to nothing (#263). It is
// cutCredentialBeforeProse's cut for a residue that carries no scheme word:
// the payload head decodes, the residue behind it does not, so no earlier
// arm in this judge fires — and no later pass can reach the payload either,
// because every pass reads a credential only behind a scheme word or header
// it looks for first — and the payload shipped whole.
//
// The cut is refused when the residue still carries a live mid-word shape —
// a scheme word the prose continues with credential material decoding
// behind it (#240). The mid-word judgement splits at the word and redacts
// both sides; the greedy cut below would swallow the word and strand the
// credential behind it inside the residue, where "[REDACTED]"'s brackets
// block every later pass from reading it back. Callers that reach this
// judge have already had that judgement decline on the same text, so the
// refusal only bites where the judge runs without it — a join segment the
// join judge faces on its own — and leaves the shape to the mid-word
// judgement the join's caller or second sweep runs instead.
//
// The cut boundary is the longest prefix that decodes: a shorter one would
// leave decodable alphabet behind the cut that no later pass can read. An
// extension of the payload by further letters often decodes too — a
// password byte may be anything above the control range, so the tail of
// "dXNlcjpwYXNzprose" reads as two more password bytes — and the cut cannot
// tell such an extension apart from a longer credential, so it takes the
// longest: the word right behind the payload can lose its head letters, or
// at the limit be swallowed through whole. That is the same
// cannot-tell-apart trade-off #217 accepted at piece granularity, paid here
// in the prose that sits directly behind a live payload; prose with no
// decodable head in front of it is untouched.
//
// The residue behind the boundary is judged, not trusted to be prose: a
// residue that is a credential of its own is swallowed whole — re-emitting
// it would strand it behind "[REDACTED]"'s brackets, where no later pass
// can read it back (#240's premise keeps such a remainder for the
// whole-value arms, but here the whole run already declined, so nobody
// else will come for it) — and a residue that carries separator-split
// credential pieces loses the pieces that decode while its prose pieces
// stay readable, the granularity judgeTail already answers for. The glue
// beyond the trimmed candidate is already off it and goes with the
// redaction, as it does for a wholesale one.
//
// The boundary costs one decode per client alphabet however long the run
// is: a base64 prefix decodes to the matching prefix of the whole byte
// stream, so one decode of each alphabet's clean head answers every prefix
// length (credentialRunBoundary).
func cutCredentialBeforeResidue(trimmed string) (string, bool) {
	i, ok := credentialRunBoundary(trimmed)
	if !ok {
		return "", false
	}
	for _, m := range embeddedSchemeWord.FindAllStringIndex(trimmed, -1) {
		if m[1] >= len(trimmed) {
			continue
		}
		c := trimmed[m[1]]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			// A word the prose continues: the residue behind it is
			// decoded as a whole, so the cut would swallow the word and
			// strand the credential inside it (#240).
			if decodesToBasicCredential(strings.Trim(trimmed[m[1]:], schemeGlue)) ||
				decodesToBasicCredential(strings.Trim(trimmed[m[1]:], "=_-")) {
				return "", false
			}
		}
		// A word the cut would swallow while a credential behind it
		// survives whole inside the residue, where "[REDACTED]"'s
		// brackets block every later pass from reading it back (#240).
		// The cut covers what comes before the boundary, so a credential
		// behind the word is stranded only when the boundary stops at or
		// before the word's end; a cut that reaches past it already took
		// the credential with it, and refusing then would hand the shape
		// to a judgement that reads the run in pieces and can no longer
		// decode what the whole-run cut could (issue #262).
		if i <= m[1] && segmentHoldsCredential(trimmed[m[1]:]) {
			return "", false
		}
	}
	rest := trimmed[i:]
	if rest == "" {
		return "", false
	}
	if decodesToBasicCredential(rest) ||
		decodesToBasicCredential(strings.Trim(rest, schemeGlue)) {
		// The boundary's leftover bits are what kept the whole run from
		// decoding, so the residue is a credential of its own and no
		// later pass reads it back out of a re-emit.
		return "[REDACTED]", true
	}
	if judged := judgeResiduePieces(rest); judged != rest {
		return "[REDACTED]" + judged, true
	}
	return "[REDACTED]" + rest, true
}

// judgeResiduePieces judges the separator-split pieces of a residue at the
// granularity judgeTail answers for (#217): a piece that decodes goes
// whole, a piece that cannot be told apart from a file name that decodes
// stays. A piece that carries the #263 shape one piece down — a decodable
// credential head the gate cannot separate from the prose behind it —
// loses the head and keeps the prose, the same cut the residue's segment
// got at segment granularity. The pieces are split on the same separators
// judgeTail splits on, and a percent-encoded separator is copied as the
// three bytes its token names, for the reason judgeTail's comment records.
func judgeResiduePieces(residue string) string {
	var out strings.Builder
	for i := 0; i < len(residue); {
		if c := residue[i]; c == '.' || c == '%' || c == '=' {
			if c == '%' && i+2 < len(residue) && isHexDigit(residue[i+1]) && isHexDigit(residue[i+2]) {
				out.WriteString(residue[i : i+3])
				i += 3
				continue
			}
			out.WriteByte(c)
			i++
			continue
		}
		end := i
		for end < len(residue) {
			if c := residue[end]; c == '.' || c == '%' || c == '=' {
				break
			}
			end++
		}
		out.WriteString(judgeResiduePiece(residue[i:end]))
		i = end
	}
	return out.String()
}

// judgeResiduePiece judges one separator-split piece of a residue. A piece
// that decodes whole is payload; one that starts with a credential the
// gate cannot separate from the prose behind it loses the credential; a
// piece with no decodable head is prose or a file name and stays.
func judgeResiduePiece(piece string) string {
	if decodesToBasicCredential(piece) {
		return "[REDACTED]"
	}
	if i, ok := credentialRunBoundary(piece); ok {
		return "[REDACTED]" + piece[i:]
	}
	return piece
}

// credentialRunBoundary reports the longest prefix of run that decodes to a
// basic-auth credential under any client alphabet. One decode per alphabet
// answers every prefix length: a base64 prefix decodes to the matching
// prefix of the whole byte stream, so the decode of an alphabet's clean
// head — the run up to its first byte the alphabet does not carry, short of
// a final character the length %4==1 wastes — is the byte stream every
// prefix of that head decodes to. On those bytes the credential condition
// is one interval of lengths: the first colon fixes the user part, and the
// password part keeps its bytes valid up to the first one below 0x20 or at
// 0x7f, so the longest boundary is the top of the interval mapped back to
// characters (a byte length k needs the shortest character count whose
// decoded bytes carry k bytes, which is never a length ≡1 mod 4).
func credentialRunBoundary(run string) (int, bool) {
	best := 0
	for _, alph := range credentialAlphabets {
		t := len(run)
		for i := 0; i < len(run); i++ {
			if strings.IndexByte(alph.chars, run[i]) < 0 {
				t = i
				break
			}
		}
		if t%4 == 1 {
			// The head's last character carries only leftover bits
			// nothing behind it can use, and its length decodes under
			// no alphabet: drop it, the boundary cannot sit on it.
			t--
		}
		if t <= 0 {
			continue
		}
		b, err := alph.decode.DecodeString(run[:t])
		if err != nil {
			continue
		}
		j := bytes.IndexByte(b, ':')
		if j <= 0 {
			continue
		}
		userOK := true
		for _, c := range b[:j] {
			if c < 0x20 || c > 0x7e {
				userOK = false
				break
			}
		}
		if !userOK {
			continue
		}
		k := len(b)
		for p := j + 1; p < len(b); p++ {
			if b[p] < 0x20 || b[p] == 0x7f {
				k = p
				break
			}
		}
		var i int
		switch k % 3 {
		case 0:
			i = k / 3 * 4
		case 1:
			i = (k*4 + 2) / 3
		case 2:
			i = (k*4 + 1) / 3
		}
		if i > best {
			best = i
		}
	}
	return best, best > 0
}

// cutCredentialBeforeProse redacts the credential that sits in front of a
// scheme word the prose continues. A scheme word glued inside a run is a
// scheme word only when the prose does not follow it: "dXVpZDpwYXNzbasic"
// carries the word as the context of whatever comes behind it, and
// "dXVpZDpwYXNzbasically" does not — "basically" is an ordinary word, and
// the credential in front of it is unreachable to every later pass, because
// no pass reads a credential that sits in front of the scheme word it looks
// for first.
//
// The head must decode to a credential and the remainder behind the word
// must not: a remainder that decodes is a credential of its own, and it is
// the middle-word judgement's business (#240), not this one's. Nothing that
// decodes is orphaned here, because the remainder does not decode.
func cutCredentialBeforeProse(seg string) (string, bool) {
	for _, m := range embeddedSchemeWord.FindAllStringIndex(seg, -1) {
		if m[1] >= len(seg) {
			// The word ends the segment: it is a scheme word, and the
			// #227 cut is its business.
			continue
		}
		c := seg[m[1]]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			// A word followed by a non-letter is a scheme word glued to
			// what follows it, and the #227 and #240 cuts skip it.
			continue
		}
		head := strings.TrimRight(seg[:m[0]], schemeGlue)
		if head == "" || !decodesToBasicCredential(head) {
			continue
		}
		rest := strings.TrimLeft(seg[m[1]:], schemeGlue)
		if rest != "" && decodesToBasicCredential(rest) {
			continue
		}
		return "[REDACTED]" + seg[m[0]:], true
	}
	return "", false
}

// judgeTail redacts the credential material a captured tail carries
// (#226). A match the decode test declines leaves its tail in play raw,
// and no later pass can read a credential that sits before the scheme
// word the pass looks for first, so the tail's material survived every
// pass and reached the digest. Judging it on the way out replaces every
// piece of credential alphabet that decodes to a user:password pair with
// "[REDACTED]". Inside a tail a piece that decodes to a credential cannot
// be told apart from a file name that decodes to one, so the piece goes
// whole — the trade-off #217 accepted for the re-emission path, at piece
// granularity. A piece that does not decode whole but starts with a
// credential the gate cannot separate from the prose behind it loses that
// head and keeps the prose (#263), the same cut the segment judge answers
// for one level down. The glue between pieces (dots, equals signs, percent
// tokens) and the pieces that decode to nothing survive: prose, file
// names and the separator context later passes may still need stay readable, which is
// why the pieces are judged instead of redacting the interior wholesale.
// The pieces are split by hand, not with basicAuthCredentialRun, for the
// same reason the scheme pass captures the encoded separators apart from
// its word chain: a token's hex digits would glue onto the run behind a
// percent-encoded separator ("%3DdXNlcjpwYXNz" reads as one run) and
// break the candidate's decode, so material behind a percent-encoded
// glue survived.
func judgeTail(tail string) string {
	var out strings.Builder
	for i := 0; i < len(tail); {
		if c := tail[i]; c == '.' || c == '%' || c == '=' {
			// Glue: a dot and an equals sign separate tokens (the latter
			// is a separator a key=value join placed before the piece
			// behind it, not padding — the word chain stops at one for
			// the same reason, issue #224), and a token's hex digits are
			// what a percent-encoded separator looks like to the next
			// pass ("%3D" names "="); all are copied verbatim and start
			// no piece, so the pieces behind them keep their own decode.
			if c == '%' && i+2 < len(tail) && isHexDigit(tail[i+1]) && isHexDigit(tail[i+2]) {
				out.WriteString(tail[i : i+3])
				i += 3
				continue
			}
			out.WriteByte(c)
			i++
			continue
		}
		end := i
		for end < len(tail) {
			if c := tail[end]; c == '.' || c == '%' || c == '=' {
				break
			}
			end++
		}
		if decodesToBasicCredential(tail[i:end]) {
			out.WriteString("[REDACTED]")
		} else if n, ok := credentialRunBoundary(tail[i:end]); ok {
			// A piece the gate refuses whole can still start with a
			// credential the gate cannot separate from the prose behind
			// it (#263) — the same shape one piece down. The head goes
			// and the prose behind it stays, the same cut the segment
			// judge answers for.
			out.WriteString("[REDACTED]" + tail[i+n:end])
		} else {
			out.WriteString(tail[i:end])
		}
		i = end
	}
	return out.String()
}

// isHexDigit reports whether c is one of the hex digits a
// percent-encoded token's second and third bytes are made of.
func isHexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'F' || 'a' <= c && c <= 'f'
}

// stripBasicAuth redacts HTTP basic-auth credentials. A header that names
// the Basic scheme is redacted on its context: RFC 7235 puts the credential
// right after the scheme, so whatever sits there goes even when it is too
// mangled to decode, because half a credential still authenticates as much
// as a whole one does. A value without the scheme word, and a bare "basic
// <token>" outside any header, carry no such context, so they are redacted
// only when they decode to a credential. Prose survives: "basic
// authentication failed" is not a credential and must stay readable.
func stripBasicAuth(s string) string {
	// A consumed tail can stop exactly on the next credential's scheme word;
	// a pass cannot rescan what it emitted, so run to a fixed point.
	// It converges: every mutating pass replaces at least one credential-
	// alphabet run — a core in either pass, a word-chain run in the scheme
	// pass — with "[REDACTED]", whose brackets match neither pattern's
	// classes and cannot join runs, so the amount of credential material
	// strictly drops and no pass can splice new credential material together.
	// Re-emitted material is context, not credential: a safeTail re-emits a
	// redacted substring of its tail, splitGluedSchemeWord re-emits only the
	// glue and the trailing scheme word it refused to redact (also for the
	// join-segment cuts redactJoinSegments takes), the cutGluedSchemeWord
	// arm — and the join-segment cuts that share it — re-emit only the split
	// word plus a strict subset of the consumed run, a non-empty head that
	// decoded is dropped and never restored, and the leading glue a join
	// segment sheds stays where the line carried it — and the
	// redactGluedWordSegments arm re-emits only words and segments the gate
	// refused — so the credential material outside the inert
	// "[REDACTED]" tokens strictly drops on every mutating pass and no pass
	// can re-create work. Declined-match tails are also judged by
	// judgeTail before any credential-bearing pieces can be re-emitted, and
	// a declined join arm replaces a gate-passing segment with
	// "[REDACTED]" plus only what cutGluedSchemeWord would re-emit — the
	// split word and a strict subset of the segment — so neither arm can
	// re-arrange credential material into a run the next pass would
	// misjudge. The shared judge (judgeSingleSegment) adds no material of
	// its own either: it re-emits the leading glue it found, the scheme
	// word and the prose behind a credential it redacted, and a tail it
	// judged — all of which the gate already refused — so the credential
	// material it drops strictly drops and the pass cannot re-create work.
	for {
		once := s
		s = redactBasicHeader(s)
		s = redactBasicScheme(s)
		if s == once {
			return s
		}
	}
}

// redactBasicHeader redacts the credential an Authorization-style header
// carries. The scan is by hand for the same reason as the scheme scan: a
// match that fails the decode gate must not swallow the text behind it,
// because that text can hold a header of its own with a credential in it
// ("Authorization-foo.Authorization:<credential>"). The scan continues from
// the value, so the later header is still read.
func redactBasicHeader(s string) string {
	var out strings.Builder
	pos := 0
	for pos < len(s) {
		loc := basicAuthHeaderPattern.FindStringSubmatchIndex(s[pos:])
		if loc == nil {
			break
		}
		// Groups: 1 = the prefix, 2 = the scheme group, 3 = the scheme
		// word, 4 = the value, 5 = the tail.
		prefix := s[pos+loc[2] : pos+loc[3]]
		scheme := ""
		if loc[6] >= 0 {
			scheme = s[pos+loc[6] : pos+loc[7]]
		}
		value := s[pos+loc[8] : pos+loc[9]]
		tail := ""
		if loc[10] >= 0 {
			tail = s[pos+loc[10] : pos+loc[11]]
		}
		// A header that kept its separator says the value is a header
		// value, so the scheme word may speak for it: a mangled credential
		// still authenticates as much as a whole one. A header separated
		// from its value by whitespace alone says less — "Authorization
		// Basic scheme is deprecated" is prose — so that form has to earn
		// the redaction on the value alone. The header name is a fixed
		// literal, so a ":" or "=" in the prefix can only be the separator
		// that was kept.
		if !decodesToBasicCredential(value) &&
			(scheme == "" || !strings.ContainsAny(prefix, ":=")) {
			// The value can be a credential joined to the token after it
			// by "=": an interior "=" is no valid base64, the gate failed
			// on the joined run, and the credential kept its plaintext
			// (issues #230, #246). The join segments face the shared
			// judge below — a credential in either slot goes, and a
			// gate-failing segment still loses the glued scheme word or
			// the leading glue it carries (issue #259). The join stays
			// readable for the same reason the scheme pass keeps it. A
			// match that carries the scheme word stays in play instead:
			// the scheme pass sees the same slot and its passes keep the
			// following credential's context alive.
			joined, joinRedacted := redactJoinSegments(value)
			if valueOut, changed := redactGluedWordSegments(value); changed && !joinRedacted {
				// A scheme word the value class swallowed into its middle,
				// with credential material beside it (#240), or a word
				// glued to the value by "+"/"/" (issue #240): the join
				// judge saw no credential in the value's segments, so the
				// segments the word splits face the gate here and the
				// word stays as context.
				out.WriteString(s[pos : pos+loc[8]])
				out.WriteString(valueOut)
				if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
					out.WriteString(safeTail(tail))
				}
				pos += loc[1]
				continue
			}
			if scheme == "" {
				if cut, ok := splitGluedSchemeWord(value); ok {
					// The value is a credential with a scheme or header
					// word glued to its end: the value class swallowed
					// both, the gate failed on the combined run, and the
					// credential survived (#227). Redact the credential
					// part and keep the glue and the word, which keeps
					// the context of whatever follows it.
					head := strings.TrimRight(value[:cut], "=_-")
					out.WriteString(s[pos : pos+loc[8]])
					out.WriteString("[REDACTED]")
					out.WriteString(value[len(head):])
					if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
						out.WriteString(safeTail(tail))
					}
					pos += loc[1]
					continue
				}
			}
			if !joinRedacted {
				if judgedValue, changed := judgeSingleSegment(value); changed {
					// The value is no credential as a whole, but one hides
					// behind the glue it carries or in front of a scheme
					// word the prose continues (#260). The shared judge
					// redacts it and keeps the glue where the line carried
					// it. A value the join judge judged is left alone: the
					// join's own shapes are the ones the line reads.
					out.WriteString(s[pos : pos+loc[8]])
					out.WriteString(judgedValue)
					// The tail belongs to the value, and the credential the
					// judge found does not reach it — the tail follows the
					// prose, not the payload — so it is judged on its own
					// and stays visible. A tail that stops on a scheme word
					// carries the next credential's context, and that one
					// goes with the redaction (#217).
					if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
						out.WriteString(safeTail(tail))
					} else {
						out.WriteString(judgeTail(tail))
					}
					pos += loc[1]
					continue
				}
			}
			// Not a credential: the value is prose, a file name or the
			// value another scheme gave the header, and it stays
			// readable. The tail, though, its character class swallows
			// whole credential segments, and a declined match leaves its
			// tail in play raw — no later pass can read a credential that
			// sits before the scheme word it looks for first, so the tail
			// is judged before it stays (#226). The match is then
			// consumed, because the tail has been written already.
			//
			// The value's own class folds an "=" join into one
			// undecodable value the same way, so a credential behind the
			// separator is never a piece either gate reaches (#246); its
			// segments faced the gate above, as the scheme core's do (#238).
			if tail != "" {
				if judged := judgeTail(tail); judged != tail {
					out.WriteString(s[pos : pos+loc[8]])
					out.WriteString(joined)
					out.WriteString(judged)
					pos += loc[1]
					continue
				}
			}
			if joinRedacted {
				// Consume only through the value: the tail has been
				// judged to carry nothing, but a later header can hide
				// in it, and the scan must still read it. The unjudged
				// segments are re-emitted verbatim, so scheme words and
				// separators the later passes need keep their shape, and
				// the fixed-point loop re-runs on the changed text.
				out.WriteString(s[pos : pos+loc[8]])
				out.WriteString(joined)
				pos += loc[9]
				continue
			}
			// A tail with nothing to redact changes nothing, so the value
			// and the tail stay in play: a later header can hide in them.
			out.WriteString(s[pos : pos+loc[8]])
			pos += loc[8]
			continue
		}
		// The text before the match and the prefix itself stay: the
		// header name is what tells the operator that a credential was
		// stripped.
		out.WriteString(s[pos : pos+loc[3]])
		if word, rest, ok := cutGluedSchemeWord(value); ok {
			out.WriteString("[REDACTED] " + word)
			if rest != "" {
				out.WriteString(" " + rest)
			}
		} else {
			out.WriteString("[REDACTED]")
		}
		// A tail that stops on a scheme word is emitted, so the next
		// credential keeps its context, but only once safeTail has
		// redacted the credential material it carries (#217). A tail
		// that stops on no scheme word goes with the credential.
		if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
			out.WriteString(safeTail(tail))
		}
		pos += loc[1]
	}
	out.WriteString(s[pos:])
	return out.String()
}

// redactBasicScheme redacts a Basic-scheme credential that no header name
// introduces. The scan is by hand because a match that fails the decode gate
// must not swallow the tail behind it: the tail can carry the next
// credential's scheme word ("basic <not-a-credential>.basic <credential>"),
// and a swallowed scheme word orphans that credential, because the
// fixed-point pass cannot see it any more — the line looks unchanged, so
// the loop stops. The tail is therefore kept in play when the core is no
// credential, and the scan continues from it.
func redactBasicScheme(s string) string {
	var out strings.Builder
	pos := 0
	for pos < len(s) {
		loc := basicAuthSchemePattern.FindStringSubmatchIndex(s[pos:])
		if loc == nil {
			break
		}
		// Groups: 1 = the separators after the scheme word, 2 = the
		// tolerated word chain, 3 = the core, 4 = the tail.
		words := s[pos+loc[4] : pos+loc[5]]
		core := s[pos+loc[6] : pos+loc[7]]
		tail := ""
		if loc[8] >= 0 {
			tail = s[pos+loc[8] : pos+loc[9]]
		}
		// Every credential-shaped run in the word chain faces the gate
		// itself, leftmost first, so the strict form "basic <credential>"
		// is judged before any word behind it — the greedy chain used to
		// swallow the credential and judge the word after it (#224).
		judged := basicAuthCredentialRun.ReplaceAllStringFunc(words, func(run string) string {
			if decodesToBasicCredential(run) {
				return "[REDACTED]"
			}
			if cut, ok := splitGluedSchemeWord(run); ok {
				// The run is a credential with a scheme word glued to
				// its end: the gate fails on the combined run, so redact
				// the credential part and re-emit the word, which the
				// next pass reads as context (#227).
				return "[REDACTED]" + run[cut:]
			}
			if segOut, changed := redactGluedWordSegments(run); changed {
				// A scheme word inside the run, with credential material
				// on both sides (#240): the gate judges the segments the
				// word splits, so a credential before and behind it go
				// while the word stays readable.
				return segOut
			}
			if segOut, changed := judgeSingleSegment(run); changed {
				// A credential the run hides behind the glue on its edge
				// or in front of a scheme word the prose continues: the
				// shared judge trims the glue and redacts the payload
				// (#260). The chain swallows the credential and its
				// separator as one token, so the arms above never see it.
				return segOut
			}
			return run
		})
		if !decodesToBasicCredential(core) {
			// A credential joined to a key by "=" could not decode as a
			// whole (interior "=" is not valid base64), so the core reached
			// here undecoded and its credential kept plaintext (issue #238).
			// Judge each join segment on its own: a credential in either
			// slot goes, the key and the join stay readable, and a segment
			// that is no credential is untouched. This also judges the slot
			// before the first "=", so the key-slot contract of #230 holds
			// which is already merged in #237. The tail follows
			// the rule of a redacted core, not a surviving one.
			if joined, ok := redactJoinSegments(core); ok {
				out.WriteString(s[pos : pos+loc[4]])
				out.WriteString(judged)
				out.WriteString(joined)
				if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
					out.WriteString(safeTail(tail))
				}
				pos += loc[1]
				continue
			} else if cut, ok := splitGluedSchemeWord(core); ok {
				// The core is a credential with a scheme word glued to its
				// end — no "=" the branch above could cut on, or a word
				// hanging on a letter the word chain could not catch
				// (issue #227). Redact the credential part and keep the
				// glue and the word: the glue is the join the line
				// carried (the "="-join above keeps its "="), and the
				// word stays because it is the context the next pass
				// reads the following credential with.
				head := strings.TrimRight(core[:cut], "=_-")
				out.WriteString(s[pos : pos+loc[4]])
				out.WriteString(judged)
				out.WriteString("[REDACTED]")
				out.WriteString(core[len(head):])
				if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
					out.WriteString(safeTail(tail))
				}
				pos += loc[1]
				continue
			} else if coreOut, changed := redactGluedWordSegments(core); changed {
				// A scheme word in the core's middle, with credential
				// material on one or both sides (#240): every credential
				// in the core faces the gate, the word and every kept
				// segment stay visible, and the tail follows the rule of
				// a redacted core, not a surviving one.
				out.WriteString(s[pos : pos+loc[4]])
				out.WriteString(judged)
				out.WriteString(coreOut)
				if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
					out.WriteString(safeTail(tail))
				}
				pos += loc[1]
				continue
			} else if coreJudged, changed := judgeSingleSegment(core); changed {
				// The core is no credential as a whole, but one hides
				// behind the glue it carries or in front of a scheme word
				// the prose continues (#260). The shared judge redacts it
				// and keeps the glue where the line carried it. The arms
				// above come first: they read the word the core carries,
				// and the word is the context a credential behind it is
				// read with.
				out.WriteString(s[pos : pos+loc[4]])
				out.WriteString(judged)
				out.WriteString(coreJudged)
				// The tail follows the core's prose, not the payload the
				// judge found, so it is judged on its own and stays
				// visible; a tail that stops on a scheme word carries the
				// next credential's context and goes with the redaction
				// (#217).
				if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
					out.WriteString(safeTail(tail))
				} else {
					out.WriteString(judgeTail(tail))
				}
				pos += loc[1]
				continue
			}
			// The scheme word alone does not say that what follows it is
			// a credential; the decode test decides that. The core stays
			// unread and in play: it can be the next credential's own
			// scheme word ("basic Basic%3D<cred>"), and a swallowed one
			// orphans that credential. A word run that did decode is
			// written redacted; the rest of the chain stays behind the
			// resume point untouched.
			if judged != words {
				out.WriteString(s[pos : pos+loc[4]])
				out.WriteString(judged)
			} else {
				out.WriteString(s[pos : pos+loc[6]])
			}
			// The tail a declined match leaves in play raw carries
			// credentials no later pass can reach, so it is judged
			// (#226) first; the core was written along the match and the
			// match is consumed. A tail with nothing to redact keeps the
			// core in play, as it can be the next credential's own scheme
			// word (see above).
			if tail != "" {
				if judged := judgeTail(tail); judged != tail {
					out.WriteString(core)
					out.WriteString(judged)
					pos += loc[1]
					continue
				}
			}
			pos += loc[6]
			continue
		}
		// The scheme word stays visible: outside a header it is the only
		// context that says a credential was here. A tail that stops on
		// a scheme word is emitted only once safeTail has redacted the
		// material it carries (#217); a tail that stops on no scheme
		// word goes with the credential.
		out.WriteString(s[pos : pos+loc[4]])
		out.WriteString(judged)
		if word, rest, ok := cutGluedSchemeWord(core); ok {
			out.WriteString("[REDACTED] " + word)
			if rest != "" {
				out.WriteString(" " + rest)
			}
		} else {
			out.WriteString("[REDACTED]")
		}
		if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
			out.WriteString(safeTail(tail))
		}
		pos += loc[1]
	}
	out.WriteString(s[pos:])
	return out.String()
}

// redactJoinSegments judges the "=" -separated segments of a core — or of a
// declined header value, whose class admits "=" (#246) — that already failed
// to decode as a whole, and reports it with every segment decoding to a
// basic-auth credential replaced by "[REDACTED]". An
// interior "=" is not valid base64, so a credential joined to a key
// ("key=<credential>") or two credentials joined together
// ("<credential>=<credential>") cannot decode as a whole and the whole-core
// gate rejects them, keeping their plaintext (issue #238). Each segment
// faces the gate on its own, so the credential goes while a non-credential
// key or value stays readable. A gate-passing segment that carries a scheme
// word glued inside it re-emits that word (and its decodable remainder) the
// way an accepted run does, so the credential behind the word stays
// reachable to a later pass (#246). A segment that fails the gate on its
// own is not re-emitted verbatim either: it can still lose the glued
// scheme word or the leading glue it carries (issue #259). A join that
// produced a redaction anywhere also judges the gate-failing segments the
// cuts left whole for a scheme word in their middle (#240). It reports false
// when the core carries no "=" or when no segment produces a redaction, so
// a plain prose "key=value" is returned
// unchanged and the caller leaves it in play.
func redactJoinSegments(core string) (string, bool) {
	if !strings.Contains(core, "=") {
		return core, false
	}
	parts := strings.Split(core, "=")
	// touched marks the parts the arms below already judged, so the second
	// sweep re-judges only what they left whole.
	touched := make([]bool, len(parts))
	redacted := false
	for i, part := range parts {
		if !decodesToBasicCredential(part) {
			// A segment that fails the gate on its own is not re-emitted
			// verbatim either: it can still lose the glued scheme word or
			// the leading glue it carries (issue #259).
			if cut, ok := splitGluedSchemeWord(part); ok {
				head := strings.TrimRight(part[:cut], "=_-")
				parts[i] = "[REDACTED]" + part[len(head):]
				touched[i] = true
				redacted = true
				continue
			}
			if word, rest, ok := cutGluedSchemeWord(part); ok {
				// A word the "=_-" trim cannot reach — glue like "+" or "/"
				// leads it, and the glue-only decode test in
				// splitGluedSchemeWord refuses the head. The #242 cut drops
				// the glue and re-emits the word with a real space, the
				// context the credential behind it is read with on the next
				// pass; redacting the part wholesale would swallow that word
				// and orphan the credential.
				parts[i] = "[REDACTED] " + word
				if rest != "" {
					parts[i] += " " + rest
				}
				touched[i] = true
				redacted = true
				continue
			}
			if judged, ok := judgeSingleSegment(part); ok {
				// The part fails the gate as a whole, but the glue it
				// carries hides the credential from it: the shared judge
				// trims the glue, redacts the payload behind it and keeps
				// the glue where the line carried it.
				parts[i] = judged
				touched[i] = true
				redacted = true
				continue
			}
			// No cut fired: the part keeps its text for the second sweep
			// below, or for the caller if the join never redacts.
			continue
		}
		// The segment goes whole, but a scheme word glued inside it is
		// re-emitted with a real space, exactly as an accepted run does:
		// the alphabets admit "_" and friends, so "cred_basic" passes the
		// gate, and the word inside it is the context the NEXT
		// credential sits behind. Swallowing it would leave that
		// credential unreachable to every later pass (#246).
		if word, rest, ok := cutGluedSchemeWord(part); ok {
			parts[i] = "[REDACTED] " + word
			if rest != "" {
				parts[i] += " " + rest
			}
		} else {
			parts[i] = "[REDACTED]"
		}
		touched[i] = true
		redacted = true
	}
	// A join that redacted anywhere holds a credential, so the gate-declining
	// parts the cuts left whole still face the middle-word judgement (#240):
	// a credential beside the word goes while the word stays readable. The
	// sweep runs after the cuts because a cut can expose the credential only
	// in a later part ("+<cred>=<word>-<cred>", #240 review): the glue the
	// cut trims keeps the whole-part decode test from seeing the credential,
	// so judging during the first pass — keyed on whole-part decodes, as the
	// pre-scan this sweep replaces was — skipped the word-split for the part
	// behind the cut and shipped its payload. A join nothing above redacted
	// reports no credential: its segments stay whole for the caller's
	// judgement, which keeps a join's key slot intact when nothing in it
	// decodes ("key=<cred><word>…", issue #240).
	if redacted {
		for i, part := range parts {
			if touched[i] {
				continue
			}
			if segOut, changed := redactGluedWordSegments(part); changed {
				// A part that carries a scheme word faces the
				// middle-word judgement (#240): a credential beside the
				// word goes while the word and any gasping join face
				// stay readable, which the part-fitting gate reading
				// the whole part leaves in play.
				parts[i] = segOut
			}
		}
	}
	if !redacted {
		return core, false
	}
	return strings.Join(parts, "="), true
}

// decodesToBasicCredential reports whether cand is base64 of a
// "user-id:password" pair, which is what RFC 7617 basic credentials are.
// The decoded bytes must read like that pair — a printable user-id, then a
// colon, then a password — because ordinary words also decode to bytes
// holding a colon ("open" decodes to bytes that start with one), and
// redacting prose would delete evidence.
func decodesToBasicCredential(cand string) bool {
	b, ok := decodeBase64(cand)
	if !ok {
		return false
	}
	i := bytes.IndexByte(b, ':')
	if i <= 0 {
		return false
	}
	for _, c := range b[:i] {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	for _, c := range b[i+1:] {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// decodeBase64 decodes a candidate in any of the alphabets a client may have
// used, padded or not.
func decodeBase64(cand string) ([]byte, bool) {
	if b, err := base64.StdEncoding.DecodeString(cand); err == nil {
		return b, true
	}
	trimmed := strings.TrimRight(cand, "=")
	if b, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil {
		return b, true
	}
	if b, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil {
		return b, true
	}
	return nil, false
}

// stripSecrets replaces obvious secrets in log lines with [REDACTED].
func stripSecrets(s string) string {
	s = stripBasicAuth(s)
	for _, p := range secretPatterns {
		if p.guard == nil {
			s = p.re.ReplaceAllString(s, p.repl)
			continue
		}
		s = p.re.ReplaceAllStringFunc(s, func(m string) string {
			if !p.guard(m) {
				return m
			}
			return p.re.ReplaceAllString(m, p.repl)
		})
	}
	return s
}

// safeMetadataValue renders one alert label or annotation value for a
// model-visible or durable surface: pod logs are already stripped at the
// fetch, but alert metadata reaches the digest, the prompt, the GitHub issue
// and the PR body verbatim unless a renderer redacts it (issue #269).
//
// A credential whose KEY names it ("password": "hunter2") matches no value
// pattern, so values under a credential-shaped key are replaced whole. The
// key itself stays so the operator can see what was stripped.
func safeMetadataValue(k, v string) string {
	if isCredentialKey(k) {
		return "[REDACTED]"
	}
	return stripSecrets(v)
}

// credentialKeyFragments are key-name fragments that declare a value to be a
// credential: a label or annotation literally named password/token/secret
// carries a secret even when the value alone matches none of stripSecrets'
// patterns. Matching is on the lowercased name with separators removed so
// api_key, api-key and apiKey read alike. Like the JSON-key pattern in
// secretPatterns this over-redacts innocent names ("note_password"); fail-safe
// beats leak on a durable record. "key" alone is not a fragment — it appears
// in unrelated names — while the compound forms (apikey, accesskey,
// privatekey) are unambiguous.
var credentialKeyFragments = []string{
	"password", "passwd", "pwd", "token", "bearer", "secret",
	"credential", "apikey", "accesskey", "privatekey", "authorization",
}

var credentialKeySeparator = strings.NewReplacer("_", "", "-", "", ".", "", " ", "")

func isCredentialKey(k string) bool {
	n := credentialKeySeparator.Replace(strings.ToLower(k))
	for _, frag := range credentialKeyFragments {
		if strings.Contains(n, frag) {
			return true
		}
	}
	return false
}
