package guard

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var body = []byte(`{"type":"invoice.paid"}`)

func hexMAC(secret string, msg []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil))
}

func jsonHook(header ...string) Hook {
	h := Hook{Header: http.Header{}, ContentType: "application/json", Body: body, IP: "203.0.113.7"}
	for i := 0; i+1 < len(header); i += 2 {
		h.Header.Set(header[i], header[i+1])
	}
	return h
}

func formHook(body string) Hook {
	return Hook{Header: http.Header{}, ContentType: "application/x-www-form-urlencoded", Body: []byte(body), IP: "203.0.113.7"}
}

func wantRejected(t *testing.T, err error, guard string) {
	t.Helper()
	var rejected *RejectedError
	if !errors.As(err, &rejected) || rejected.Guard != guard {
		t.Fatalf("err = %v, want a rejection by %s", err, guard)
	}
}

var (
	honeypot = Spec{Name: "honeypot", Type: Honeypot}
	github   = Spec{Name: "gh", Type: Signature, Scheme: HMAC, Secret: "gh-secret", Options: presetOptions("github")}
	stripe   = Spec{Name: "stripe-prod", Type: Signature, Scheme: Stripe, Secret: "whsec_test"}
	custom   = Spec{Name: "jobs", Type: Signature, Scheme: HMAC, Secret: "s3cret", Options: presetOptions("hmac")}
)

func presetOptions(name string) Options {
	for _, p := range Presets {
		if p.Name == name {
			return p.Options
		}
	}
	panic("no preset " + name)
}

func TestValidate(t *testing.T) {
	cases := []struct {
		typ, scheme, secret string
		opts                Options
		ok                  bool
	}{
		{Honeypot, "", "", Options{}, true},
		{Honeypot, "", "", Options{Field: "_website"}, true},
		{Honeypot, "", "", Options{Field: "my field"}, false},
		{Honeypot, "", "x", Options{}, false},
		{Captcha, Turnstile, "0x4AAA", Options{}, true},
		{Captcha, ReCAPTCHA, "6Lc", Options{}, true},
		{Captcha, ReCAPTCHA, "6Lc", Options{MinScore: 1.5}, false},
		{Captcha, "", "0x4AAA", Options{}, false},
		{Captcha, Turnstile, "", Options{}, false},
		{Captcha, HMAC, "x", Options{}, false},
		{Signature, Stripe, "whsec_1", Options{}, true},
		{Signature, HMAC, "x", presetOptions("shopify"), true},
		{Signature, HMAC, "x", Options{Algorithm: "md5"}, false},
		{Signature, HMAC, "x", Options{Encoding: "base32"}, false},
		{Signature, HMAC, "x", Options{Header: "Bad Header"}, false},
		{Token, "", "x", presetOptions("bearer"), true},
		{Token, HMAC, "x", Options{}, false},
		{Token, "", "", Options{}, false},
		{Signature, "", "x", Options{}, false},
		{Signature, "slack", "x", Options{}, false},
		{Signature, HMAC, "", Options{}, false},
		{"captcha", "", "", Options{}, false},
	}
	for _, tc := range cases {
		if _, err := Validate(tc.typ, tc.scheme, tc.secret, tc.opts); (err == nil) != tc.ok {
			t.Errorf("Validate(%q, %q, %q, %+v) = %v, want ok %v", tc.typ, tc.scheme, tc.secret, tc.opts, err, tc.ok)
		}
	}
}

func TestValidateFillsDefaults(t *testing.T) {
	opts, _ := Validate(Signature, HMAC, "x", Options{})
	if opts != (Options{Header: HMACHeader, Algorithm: "sha256", Encoding: "hex"}) {
		t.Fatalf("hmac defaults = %+v", opts)
	}
	opts, _ = Validate(Token, "", "x", Options{Algorithm: "sha1", Encoding: "hex"})
	if opts != (Options{Header: "Authorization"}) {
		t.Fatalf("token options = %+v, want the header default and no hmac fields", opts)
	}
	opts, _ = Validate(Captcha, ReCAPTCHA, "x", Options{})
	if opts != (Options{MinScore: DefaultMinScore}) {
		t.Fatalf("recaptcha defaults = %+v", opts)
	}
	opts, _ = Validate(Captcha, Turnstile, "x", Options{MinScore: 0.9})
	if opts != (Options{}) {
		t.Fatalf("turnstile options = %+v, want none", opts)
	}
	opts, _ = Validate(Signature, Stripe, "x", Options{Header: "X"})
	if opts != (Options{}) {
		t.Fatalf("stripe options = %+v, want none", opts)
	}
}

func TestHMACFormats(t *testing.T) {
	c := &Checker{}
	mac := func(newHash func() hash.Hash, secret string) []byte {
		m := hmac.New(newHash, []byte(secret))
		m.Write(body)
		return m.Sum(nil)
	}

	shopify := Spec{Name: "shop", Type: Signature, Scheme: HMAC, Secret: "shpss", Options: presetOptions("shopify")}
	if err := c.Check(t.Context(), []Spec{shopify}, jsonHook("X-Shopify-Hmac-Sha256", base64.StdEncoding.EncodeToString(mac(sha256.New, "shpss")))); err != nil {
		t.Fatalf("shopify (base64): %v", err)
	}
	wantRejected(t, c.Check(t.Context(), []Spec{shopify}, jsonHook("X-Shopify-Hmac-Sha256", hex.EncodeToString(mac(sha256.New, "shpss")))), "shop")

	legacy := Spec{Name: "legacy", Type: Signature, Scheme: HMAC, Secret: "k", Options: Options{Header: "X-Hub-Signature", Algorithm: "sha1", Encoding: "hex", Prefix: "sha1="}}
	if err := c.Check(t.Context(), []Spec{legacy}, jsonHook("X-Hub-Signature", "sha1="+hex.EncodeToString(mac(sha1.New, "k")))); err != nil {
		t.Fatalf("sha1: %v", err)
	}
	wantRejected(t, c.Check(t.Context(), []Spec{legacy}, jsonHook("X-Hub-Signature", hex.EncodeToString(mac(sha1.New, "k")))), "legacy")

	strong := Spec{Name: "strong", Type: Signature, Scheme: HMAC, Secret: "k", Options: Options{Header: "X-Sig", Algorithm: "sha512", Encoding: "hex"}}
	if err := c.Check(t.Context(), []Spec{strong}, jsonHook("X-Sig", hex.EncodeToString(mac(sha512.New, "k")))); err != nil {
		t.Fatalf("sha512: %v", err)
	}
}

func TestToken(t *testing.T) {
	c := &Checker{}
	gitlab := Spec{Name: "gl", Type: Token, Secret: "glpat-123", Options: presetOptions("gitlab")}
	bearer := Spec{Name: "bearer", Type: Token, Secret: "tok-456", Options: presetOptions("bearer")}

	if err := c.Check(t.Context(), []Spec{gitlab}, jsonHook("X-Gitlab-Token", "glpat-123")); err != nil {
		t.Fatalf("gitlab: %v", err)
	}
	wantRejected(t, c.Check(t.Context(), []Spec{gitlab}, jsonHook("X-Gitlab-Token", "glpat-999")), "gl")
	wantRejected(t, c.Check(t.Context(), []Spec{gitlab}, jsonHook()), "gl")

	if err := c.Check(t.Context(), []Spec{bearer}, jsonHook("Authorization", "Bearer tok-456")); err != nil {
		t.Fatalf("bearer: %v", err)
	}
	wantRejected(t, c.Check(t.Context(), []Spec{bearer}, jsonHook("Authorization", "tok-456")), "bearer")
}

func TestDescribe(t *testing.T) {
	if got := Describe(Signature, HMAC, presetOptions("github")); got != "signature · hmac · X-Hub-Signature-256 · sha256 hex" {
		t.Fatalf("Describe = %q", got)
	}
	if got := Describe(Token, "", presetOptions("gitlab")); got != "token · X-Gitlab-Token" {
		t.Fatalf("Describe = %q", got)
	}
	if got := Describe(Honeypot, "", Options{}); got != "honeypot" {
		t.Fatalf("Describe = %q", got)
	}
	o, err := ParseOptions(presetOptions("bearer").JSON())
	if err != nil || o != presetOptions("bearer") {
		t.Fatalf("options round trip = %+v, %v", o, err)
	}
}

func TestNoGuards(t *testing.T) {
	if err := (&Checker{}).Check(t.Context(), nil, formHook("_gotcha=bot")); err != nil {
		t.Fatalf("Check = %v, want nil", err)
	}
}

func TestHoneypotField(t *testing.T) {
	c := &Checker{}
	site := Spec{Name: "hp", Type: Honeypot, Options: Options{Field: "_website"}}
	if err := c.Check(t.Context(), []Spec{site}, formHook("a=b&_gotcha=x&_website=")); err != nil {
		t.Fatalf("other field filled, own field empty: %v", err)
	}
	if err := c.Check(t.Context(), []Spec{site}, formHook("a=b&_website=http://spam")); !errors.Is(err, ErrBot) {
		t.Fatalf("own field filled: %v, want ErrBot", err)
	}
	opts, _ := Validate(Honeypot, "", "", Options{})
	if opts.Field != "_gotcha" {
		t.Fatalf("default field = %q", opts.Field)
	}
	if got := Describe(Honeypot, "", Options{Field: "_website"}); got != "honeypot · _website" {
		t.Fatalf("Describe = %q", got)
	}
}

func TestHoneypot(t *testing.T) {
	c := &Checker{}
	if err := c.Check(t.Context(), []Spec{honeypot}, formHook("a=b&_gotcha=")); err != nil {
		t.Fatalf("empty honeypot: %v", err)
	}
	if err := c.Check(t.Context(), []Spec{honeypot}, formHook("a=b&_gotcha=x")); !errors.Is(err, ErrBot) {
		t.Fatalf("filled honeypot: %v, want ErrBot", err)
	}
	if err := c.Check(t.Context(), []Spec{honeypot}, jsonHook()); err != nil {
		t.Fatalf("JSON: %v", err)
	}
}

func TestGitHubSignature(t *testing.T) {
	c := &Checker{}
	if err := c.Check(t.Context(), []Spec{github}, jsonHook("X-Hub-Signature-256", Sign("gh-secret", body))); err != nil {
		t.Fatalf("valid signature: %v", err)
	}
	wantRejected(t, c.Check(t.Context(), []Spec{github}, jsonHook()), "gh")
	wantRejected(t, c.Check(t.Context(), []Spec{github}, jsonHook("X-Hub-Signature-256", Sign("other", body))), "gh")
	wantRejected(t, c.Check(t.Context(), []Spec{github}, jsonHook("X-Hub-Signature-256", hexMAC("gh-secret", body))), "gh")
}

func TestHMACSignature(t *testing.T) {
	c := &Checker{}
	if err := c.Check(t.Context(), []Spec{custom}, jsonHook(HMACHeader, Sign("s3cret", body))); err != nil {
		t.Fatalf("valid signature: %v", err)
	}
	wantRejected(t, c.Check(t.Context(), []Spec{custom}, jsonHook(HMACHeader, Sign("s3cret", []byte("tampered")))), "jobs")
}

func TestStripeSignature(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := &Checker{Now: func() time.Time { return now }}
	sig := func(ts time.Time, secret string) string {
		t := fmt.Sprint(ts.Unix())
		return fmt.Sprintf("t=%s,v1=%s", t, hexMAC(secret, append([]byte(t+"."), body...)))
	}

	if err := c.Check(t.Context(), []Spec{stripe}, jsonHook("Stripe-Signature", sig(now, "whsec_test"))); err != nil {
		t.Fatalf("valid signature: %v", err)
	}
	// Stripe may send several v1 signatures while rolling secrets.
	both := sig(now, "whsec_old") + ",v1=" + hexMAC("whsec_test", append([]byte(fmt.Sprint(now.Unix())+"."), body...))
	if err := c.Check(t.Context(), []Spec{stripe}, jsonHook("Stripe-Signature", both)); err != nil {
		t.Fatalf("second v1 signature: %v", err)
	}
	wantRejected(t, c.Check(t.Context(), []Spec{stripe}, jsonHook("Stripe-Signature", sig(now, "whsec_wrong"))), "stripe-prod")
	wantRejected(t, c.Check(t.Context(), []Spec{stripe}, jsonHook("Stripe-Signature", sig(now.Add(-10*time.Minute), "whsec_test"))), "stripe-prod")
	wantRejected(t, c.Check(t.Context(), []Spec{stripe}, jsonHook("Stripe-Signature", "garbage")), "stripe-prod")
}

func TestAllGuardsMustPass(t *testing.T) {
	c := &Checker{}
	good := jsonHook("X-Hub-Signature-256", Sign("gh-secret", body), HMACHeader, Sign("s3cret", body))
	if err := c.Check(t.Context(), []Spec{github, custom}, good); err != nil {
		t.Fatalf("both signatures valid: %v", err)
	}
	wantRejected(t, c.Check(t.Context(), []Spec{github, custom}, jsonHook("X-Hub-Signature-256", Sign("gh-secret", body))), "jobs")
}

func TestUnknownGuardRejects(t *testing.T) {
	c := &Checker{}
	wantRejected(t, c.Check(t.Context(), []Spec{{Name: "x", Type: "captcha"}}, jsonHook()), "x")
	wantRejected(t, c.Check(t.Context(), []Spec{{Name: "y", Type: Signature, Scheme: "slack", Secret: "s"}}, jsonHook()), "y")
	// A guard missing its header option rejects rather than passing.
	wantRejected(t, c.Check(t.Context(), []Spec{{Name: "z", Type: Token, Secret: "s"}}, jsonHook()), "z")
}

// fakeSiteverify answers like a captcha provider: "good-token" passes,
// "v3-<score>" passes with that score, anything else fails.
func fakeSiteverify(t *testing.T, got *url.Values) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		*got = r.PostForm
		switch resp := r.FormValue("response"); {
		case resp == "good-token":
			fmt.Fprint(w, `{"success":true}`)
		case strings.HasPrefix(resp, "v3-"):
			fmt.Fprintf(w, `{"success":true,"score":%s}`, strings.TrimPrefix(resp, "v3-"))
		default:
			fmt.Fprint(w, `{"success":false,"error-codes":["invalid-input-response"]}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTurnstile(t *testing.T) {
	var got url.Values
	siteverify := fakeSiteverify(t, &got)
	c := &Checker{VerifyURLs: map[string]string{Turnstile: siteverify.URL}}
	ts := Spec{Name: "site", Type: Captcha, Scheme: Turnstile, Secret: "ts-secret"}

	if err := c.Check(t.Context(), []Spec{honeypot, ts}, formHook("email=a%40b.c&cf-turnstile-response=good-token")); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	if got.Get("secret") != "ts-secret" || got.Get("response") != "good-token" || got.Get("remoteip") != "203.0.113.7" {
		t.Fatalf("siteverify got %v", got)
	}

	// A filled honeypot is caught before the provider is asked.
	got = nil
	if err := c.Check(t.Context(), []Spec{ts, honeypot}, formHook("_gotcha=x&cf-turnstile-response=good-token")); !errors.Is(err, ErrBot) || got != nil {
		t.Fatalf("bot: %v, siteverify called with %v", err, got)
	}

	// A JSON sender can pass the token in a header instead.
	if err := c.Check(t.Context(), []Spec{ts}, jsonHook("CF-Turnstile-Response", "good-token")); err != nil {
		t.Fatalf("token in header: %v", err)
	}

	wantRejected(t, c.Check(t.Context(), []Spec{ts}, formHook("cf-turnstile-response=bad-token")), "site")
	wantRejected(t, c.Check(t.Context(), []Spec{ts}, jsonHook()), "site")
	// Another provider's token doesn't count.
	wantRejected(t, c.Check(t.Context(), []Spec{ts}, formHook("g-recaptcha-response=good-token")), "site")

	// When the provider can't be reached the hook isn't rejected as invalid;
	// the caller reports the check as unavailable.
	siteverify.Close()
	err := c.Check(t.Context(), []Spec{ts}, jsonHook("CF-Turnstile-Response", "good-token"))
	var rejected *RejectedError
	if err == nil || errors.As(err, &rejected) {
		t.Fatalf("unreachable siteverify: %v, want a non-rejection error", err)
	}
}

func TestReCAPTCHA(t *testing.T) {
	var got url.Values
	siteverify := fakeSiteverify(t, &got)
	c := &Checker{VerifyURLs: map[string]string{ReCAPTCHA: siteverify.URL}}
	rc := Spec{Name: "rc", Type: Captcha, Scheme: ReCAPTCHA, Secret: "6Lc-secret", Options: Options{MinScore: 0.5}}

	// v2 answers have no score.
	if err := c.Check(t.Context(), []Spec{rc}, formHook("email=a%40b.c&g-recaptcha-response=good-token")); err != nil {
		t.Fatalf("v2 token: %v", err)
	}
	if got.Get("secret") != "6Lc-secret" || got.Get("response") != "good-token" {
		t.Fatalf("siteverify got %v", got)
	}
	// v3 answers are held to the minimum score.
	if err := c.Check(t.Context(), []Spec{rc}, formHook("g-recaptcha-response=v3-0.9")); err != nil {
		t.Fatalf("v3 score 0.9: %v", err)
	}
	wantRejected(t, c.Check(t.Context(), []Spec{rc}, formHook("g-recaptcha-response=v3-0.3")), "rc")
	// A JSON sender can pass the token in a header.
	if err := c.Check(t.Context(), []Spec{rc}, jsonHook("X-Recaptcha-Token", "good-token")); err != nil {
		t.Fatalf("token in header: %v", err)
	}
	wantRejected(t, c.Check(t.Context(), []Spec{rc}, formHook("g-recaptcha-response=bad")), "rc")
}

func TestPresets(t *testing.T) {
	// Every preset is a valid guard once given a secret, and keeps its options.
	for _, p := range Presets {
		secret := "s"
		if !NeedsSecret(p.Type) {
			secret = ""
		}
		opts, err := Validate(p.Type, p.Scheme, secret, p.Options)
		if err != nil || opts != p.Options {
			t.Errorf("preset %s: Validate = %+v, %v", p.Name, opts, err)
		}
	}

	var got []string
	for _, g := range PresetGroups() {
		got = append(got, fmt.Sprintf("%s:%d", g.Name, len(g.Presets)))
	}
	if fmt.Sprint(got) != "[Forms:3 Signatures:4 Tokens:3]" {
		t.Fatalf("groups = %v", got)
	}
}
