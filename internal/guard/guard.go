// Package guard checks incoming hooks against the guards attached to a
// channel: a form honeypot, a captcha token (Cloudflare Turnstile or Google
// reCAPTCHA), a webhook
// signature, or a shared token. Guards are configured in the database; this package only knows
// how each type checks a hook.
package guard

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/catchysh/catchy/internal/payload"
)

// Guard types.
const (
	Honeypot  = "honeypot"  // drop form posts that fill a hidden field (Options.Field)
	Captcha   = "captcha"   // require a valid captcha token, from Scheme's provider
	Signature = "signature" // require a valid webhook signature, in Scheme's format
	Token     = "token"     // require a header that holds the secret itself
)

// Types lists every guard type, in display order.
var Types = []string{Honeypot, Captcha, Signature, Token}

// Captcha schemes: which provider issued the token.
const (
	Turnstile = "turnstile" // Cloudflare Turnstile
	ReCAPTCHA = "recaptcha" // Google reCAPTCHA v2 or v3
)

// CaptchaSchemes lists every captcha scheme, in display order.
var CaptchaSchemes = []string{Turnstile, ReCAPTCHA}

// DefaultMinScore is the lowest reCAPTCHA v3 score accepted by default.
const DefaultMinScore = 0.5

// Signature schemes: how a signature guard checks a hook.
const (
	// HMAC checks an HMAC of the raw body in a header, in a configurable
	// format (see Options). GitHub and Shopify signatures are presets of it.
	HMAC = "hmac"
	// Stripe checks Stripe-Signature: t=<unix>,v1=<hex HMAC of "<t>.<body>">,
	// with a replay window.
	Stripe = "stripe"
)

// Schemes lists every signature scheme, in display order.
var Schemes = []string{HMAC, Stripe}

// HMACHeader is the default header for the hmac scheme.
const HMACHeader = "X-Catchy-Signature"

// HMAC algorithms and signature encodings.
var (
	Algorithms = []string{"sha256", "sha1", "sha512"}
	Encodings  = []string{"hex", "base64"}
)

// StripeTolerance is how old a Stripe signature's timestamp may be.
const StripeTolerance = 5 * time.Minute

// Captcha verify endpoints, and the form field and header carrying each
// provider's token.
var captchaProviders = map[string]struct {
	verifyURL, field, header string
}{
	Turnstile: {"https://challenges.cloudflare.com/turnstile/v0/siteverify", payload.TurnstileField, "CF-Turnstile-Response"},
	ReCAPTCHA: {"https://www.google.com/recaptcha/api/siteverify", payload.ReCAPTCHAField, "X-Recaptcha-Token"},
}

// Options configure hmac signature guards and token guards. Fields that don't
// apply to a guard are empty.
type Options struct {
	Field     string  `json:"field,omitempty"`     // honeypot: the hidden field that must stay empty
	Header    string  `json:"header,omitempty"`    // hmac, token: where the signature or token is
	Algorithm string  `json:"algorithm,omitempty"` // hmac: sha256, sha1, or sha512
	Encoding  string  `json:"encoding,omitempty"`  // hmac: hex or base64
	Prefix    string  `json:"prefix,omitempty"`    // hmac, token: text before the value, e.g. "sha256="
	MinScore  float64 `json:"min_score,omitempty"` // recaptcha: lowest v3 score accepted, 0–1
}

// ParseOptions decodes options stored as JSON; empty means none.
func ParseOptions(raw string) (Options, error) {
	var o Options
	if raw == "" {
		return o, nil
	}
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		return o, fmt.Errorf("decoding guard options: %w", err)
	}
	return o, nil
}

// JSON encodes options for storage.
func (o Options) JSON() string {
	b, _ := json.Marshal(o)
	return string(b)
}

// Preset is a ready-made guard configuration the dashboard offers: picking
// one sets the guard's type, scheme, and default options.
type Preset struct {
	Name        string
	Label       string
	Description string
	Group       string // "Forms", "Signatures", or "Tokens"
	Type        string
	Scheme      string
	Secret      string // the secret's suggested name, e.g. STRIPE_WEBHOOK_SECRET
	Options     Options
}

// Presets are the dashboard's guard choices, grouped, in display order.
var Presets = []Preset{
	{"honeypot", "Honeypot", "Drops form posts that fill a hidden field, quietly.", "Forms", Honeypot, "", "", Options{Field: payload.HoneypotField}},
	{"turnstile", "Cloudflare Turnstile", "Requires a Turnstile token from the form's widget.", "Forms", Captcha, Turnstile, "TURNSTILE_SECRET_KEY", Options{}},
	{"recaptcha", "Google reCAPTCHA", "Requires a reCAPTCHA token; v3 scores below the minimum fail.", "Forms", Captcha, ReCAPTCHA, "RECAPTCHA_SECRET_KEY", Options{MinScore: DefaultMinScore}},

	{"github", "GitHub", "X-Hub-Signature-256: HMAC-SHA256 of the body.", "Signatures", Signature, HMAC, "GITHUB_WEBHOOK_SECRET", Options{Header: "X-Hub-Signature-256", Algorithm: "sha256", Encoding: "hex", Prefix: "sha256="}},
	{"shopify", "Shopify", "X-Shopify-Hmac-Sha256: base64 HMAC-SHA256 of the body.", "Signatures", Signature, HMAC, "SHOPIFY_WEBHOOK_SECRET", Options{Header: "X-Shopify-Hmac-Sha256", Algorithm: "sha256", Encoding: "base64"}},
	{"stripe", "Stripe", "Stripe-Signature, with a 5-minute replay window.", "Signatures", Signature, Stripe, "STRIPE_WEBHOOK_SECRET", Options{}},
	{"hmac", "Custom HMAC", "An HMAC of the body in a header and format you choose.", "Signatures", Signature, HMAC, "WEBHOOK_SECRET", Options{Header: HMACHeader, Algorithm: "sha256", Encoding: "hex", Prefix: "sha256="}},

	{"bearer", "Bearer token", "Authorization: Bearer <token>.", "Tokens", Token, "", "API_TOKEN", Options{Header: "Authorization", Prefix: "Bearer "}},
	{"gitlab", "GitLab", "X-Gitlab-Token: <token>.", "Tokens", Token, "", "GITLAB_WEBHOOK_TOKEN", Options{Header: "X-Gitlab-Token"}},
	{"token", "Custom header", "A header you choose holds the token.", "Tokens", Token, "", "API_TOKEN", Options{Header: "X-Catchy-Token"}},
}

// PresetGroup is a group of presets, for the dashboard's picker.
type PresetGroup struct {
	Name    string
	Presets []Preset
}

// PresetGroups returns Presets grouped, in display order.
func PresetGroups() []PresetGroup {
	var groups []PresetGroup
	for _, p := range Presets {
		if n := len(groups); n == 0 || groups[n-1].Name != p.Group {
			groups = append(groups, PresetGroup{Name: p.Group})
		}
		groups[len(groups)-1].Presets = append(groups[len(groups)-1].Presets, p)
	}
	return groups
}

// Spec is a configured guard, with its secret in plaintext.
type Spec struct {
	Name    string
	Type    string
	Scheme  string // for signature guards
	Secret  string // for captcha, signature, and token guards
	Options Options
}

// Validate reports whether a guard's type, scheme, secret, and options fit
// together, and returns the options with defaults filled in and fields the
// scheme doesn't use cleared.
func Validate(typ, scheme, secret string, opts Options) (Options, error) {
	switch typ {
	case Honeypot:
		if scheme != "" || secret != "" {
			return Options{}, errors.New("a honeypot guard takes no scheme or secret")
		}
		field := opts.Field
		if field == "" {
			field = payload.HoneypotField
		}
		if err := validField(field); err != nil {
			return Options{}, err
		}
		return Options{Field: field}, nil
	case Captcha:
		if !slices.Contains(CaptchaSchemes, scheme) {
			return Options{}, fmt.Errorf("a captcha guard needs a scheme: one of %s", strings.Join(CaptchaSchemes, ", "))
		}
		if secret == "" {
			return Options{}, errors.New("a captcha guard needs the provider's secret key")
		}
		if scheme != ReCAPTCHA {
			return Options{}, nil
		}
		score := opts.MinScore
		if score == 0 {
			score = DefaultMinScore
		}
		if score < 0 || score > 1 {
			return Options{}, errors.New("the minimum score must be between 0 and 1")
		}
		return Options{MinScore: score}, nil
	case Token:
		if scheme != "" {
			return Options{}, errors.New("a token guard takes no scheme")
		}
		if secret == "" {
			return Options{}, errors.New("a token guard needs the token")
		}
		if len(opts.Prefix) > 64 {
			return Options{}, errors.New("the prefix is too long")
		}
		out := Options{Header: opts.Header, Prefix: opts.Prefix}
		if out.Header == "" {
			out.Header = "Authorization"
		}
		return out, validHeader(out.Header)
	case Signature:
	default:
		return Options{}, fmt.Errorf("unknown guard type %q: use one of %s", typ, strings.Join(Types, ", "))
	}

	if secret == "" {
		return Options{}, errors.New("a signature guard needs the signing secret")
	}
	if len(opts.Prefix) > 64 {
		return Options{}, errors.New("the prefix is too long")
	}
	switch scheme {
	case HMAC:
		out := Options{Header: opts.Header, Algorithm: opts.Algorithm, Encoding: opts.Encoding, Prefix: opts.Prefix}
		if out.Header == "" {
			out.Header = HMACHeader
		}
		if out.Algorithm == "" {
			out.Algorithm = "sha256"
		}
		if out.Encoding == "" {
			out.Encoding = "hex"
		}
		if !slices.Contains(Algorithms, out.Algorithm) {
			return Options{}, fmt.Errorf("unknown algorithm %q: use one of %s", out.Algorithm, strings.Join(Algorithms, ", "))
		}
		if !slices.Contains(Encodings, out.Encoding) {
			return Options{}, fmt.Errorf("unknown encoding %q: use one of %s", out.Encoding, strings.Join(Encodings, ", "))
		}
		return out, validHeader(out.Header)
	case Stripe:
		return Options{}, nil
	default:
		return Options{}, fmt.Errorf("a signature guard needs a scheme: one of %s", strings.Join(Schemes, ", "))
	}
}

// validField reports whether name is a usable form field name for a
// honeypot: up to 64 letters, digits, "_", "-", ".", "[" or "]".
func validField(name string) error {
	if len(name) > 64 {
		return errors.New("the field name is too long")
	}
	for _, r := range name {
		if !(r == '_' || r == '-' || r == '.' || r == '[' || r == ']' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return fmt.Errorf("invalid field name %q", name)
		}
	}
	return nil
}

// validHeader reports whether name is a usable HTTP header name.
func validHeader(name string) error {
	if len(name) > 64 {
		return errors.New("the header name is too long")
	}
	for _, r := range name {
		if !(r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return fmt.Errorf("invalid header name %q", name)
		}
	}
	return nil
}

// Describe summarizes a guard's configuration for display, e.g.
// "signature · hmac · X-Hub-Signature-256 · sha256 hex".
func Describe(typ, scheme string, opts Options) string {
	parts := []string{typ}
	if scheme != "" {
		parts = append(parts, scheme)
	}
	if opts.Field != "" {
		parts = append(parts, opts.Field)
	}
	if opts.Header != "" {
		parts = append(parts, opts.Header)
	}
	if opts.Algorithm != "" {
		parts = append(parts, opts.Algorithm+" "+opts.Encoding)
	}
	if opts.MinScore != 0 {
		parts = append(parts, fmt.Sprintf("min score %g", opts.MinScore))
	}
	return strings.Join(parts, " · ")
}

// NeedsSecret reports whether guards of a type have a secret.
func NeedsSecret(typ string) bool { return typ != Honeypot }

// Checker runs guards against hooks.
type Checker struct {
	// VerifyURLs override captcha providers' verify endpoints, by scheme, for
	// tests.
	VerifyURLs map[string]string
	// Client makes captcha verify calls; nil uses a client with a timeout.
	Client *http.Client
	// Now is the clock for Stripe timestamps; nil uses time.Now.
	Now func() time.Time
}

// ErrBot means a honeypot caught a bot. The hook should be dropped quietly,
// answering as if it succeeded so the bot doesn't adapt.
var ErrBot = errors.New("honeypot filled")

// RejectedError means a guard refused the hook; it should be answered with
// 403 and not stored.
type RejectedError struct {
	Guard  string // the guard's name
	Reason string
}

func (e *RejectedError) Error() string { return e.Guard + ": " + e.Reason }

func reject(guard, format string, args ...any) error {
	return &RejectedError{Guard: guard, Reason: fmt.Sprintf(format, args...)}
}

// Hook is what guards inspect.
type Hook struct {
	Header      http.Header
	ContentType string
	Body        []byte
	IP          string
}

// Check runs every guard against h, cheapest first; all must pass. It returns
// nil when they do, ErrBot for a filled honeypot, a *RejectedError when a
// guard refuses the hook, or another error when a check couldn't be made
// (e.g. Cloudflare is unreachable).
func (c *Checker) Check(ctx context.Context, guards []Spec, h Hook) error {
	order := map[string]int{Honeypot: 0, Token: 1, Signature: 2, Captcha: 3}
	sorted := slices.Clone(guards)
	slices.SortStableFunc(sorted, func(a, b Spec) int { return order[a.Type] - order[b.Type] })

	var fields map[string]any
	for _, g := range sorted {
		if (g.Type == Honeypot || g.Type == Captcha) && fields == nil {
			fields = payload.Raw(h.ContentType, h.Body)
		}
		switch g.Type {
		case Honeypot:
			field := g.Options.Field
			if field == "" {
				field = payload.HoneypotField // guards stored before the setting existed
			}
			if payload.Filled(fields[field]) {
				return ErrBot
			}
		case Token:
			value, ok := strings.CutPrefix(h.Header.Get(g.Options.Header), g.Options.Prefix)
			if !ok || subtle.ConstantTimeCompare([]byte(value), []byte(g.Secret)) != 1 {
				return reject(g.Name, "invalid or missing %s", g.Options.Header)
			}
		case Signature:
			if err := c.checkSignature(g, h); err != nil {
				return err
			}
		case Captcha:
			provider, ok := captchaProviders[g.Scheme]
			if !ok {
				return reject(g.Name, "unknown captcha scheme %q", g.Scheme)
			}
			token := payload.String(fields[provider.field])
			if token == "" {
				token = h.Header.Get(provider.header)
			}
			if err := c.verifyCaptcha(ctx, g, token, h.IP); err != nil {
				return err
			}
		default:
			return reject(g.Name, "unknown guard type %q", g.Type)
		}
	}
	return nil
}

func (c *Checker) checkSignature(g Spec, h Hook) error {
	switch g.Scheme {
	case HMAC:
		value, ok := strings.CutPrefix(h.Header.Get(g.Options.Header), g.Options.Prefix)
		if !ok || value == "" || !validMACIn(g.Options.Algorithm, g.Options.Encoding, g.Secret, h.Body, value) {
			return reject(g.Name, "invalid or missing %s", g.Options.Header)
		}
	case Stripe:
		return c.checkStripe(g, h)
	default:
		return reject(g.Name, "unknown signature scheme %q", g.Scheme)
	}
	return nil
}

// checkStripe verifies a Stripe-Signature header ("t=<unix>,v1=<hex>,...")
// as Stripe documents: HMAC-SHA256 of "<t>.<body>", with a fresh timestamp.
func (c *Checker) checkStripe(g Spec, h Hook) error {
	var ts string
	var sigs []string
	for _, part := range strings.Split(h.Header.Get("Stripe-Signature"), ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(sigs) == 0 {
		return reject(g.Name, "invalid or missing Stripe-Signature")
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	if age := now().Sub(time.Unix(unix, 0)); age > StripeTolerance || age < -StripeTolerance {
		return reject(g.Name, "signature timestamp outside tolerance")
	}
	signed := append([]byte(ts+"."), h.Body...)
	for _, sig := range sigs {
		if validMAC(g.Secret, signed, sig) {
			return nil
		}
	}
	return reject(g.Name, "invalid Stripe-Signature")
}

// validMAC reports whether hexSig is the HMAC-SHA256 of msg under secret.
func validMAC(secret string, msg []byte, hexSig string) bool {
	return validMACIn("sha256", "hex", secret, msg, hexSig)
}

// validMACIn reports whether sig, in encoding, is the HMAC of msg under
// secret with algorithm.
func validMACIn(algorithm, encoding, secret string, msg []byte, sig string) bool {
	var got []byte
	var err error
	switch encoding {
	case "hex":
		got, err = hex.DecodeString(sig)
	case "base64":
		got, err = base64.StdEncoding.DecodeString(sig)
	default:
		return false
	}
	if err != nil {
		return false
	}
	var newHash func() hash.Hash
	switch algorithm {
	case "sha256":
		newHash = sha256.New
	case "sha1":
		newHash = sha1.New
	case "sha512":
		newHash = sha512.New
	default:
		return false
	}
	mac := hmac.New(newHash, []byte(secret))
	mac.Write(msg)
	return hmac.Equal(got, mac.Sum(nil))
}

// Sign returns the "sha256=<hex>" signature of body, as senders compute it for
// the default hmac scheme options and GitHub.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// verifyCaptcha checks a captcha token with its provider. Turnstile and
// reCAPTCHA share the siteverify protocol: POST the secret, token, and IP; get
// back success, error codes, and for reCAPTCHA v3 a score.
func (c *Checker) verifyCaptcha(ctx context.Context, g Spec, token, ip string) error {
	if token == "" {
		return reject(g.Name, "missing token")
	}
	verifyURL := captchaProviders[g.Scheme].verifyURL
	if u := c.VerifyURLs[g.Scheme]; u != "" {
		verifyURL = u
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	form := url.Values{"secret": {g.Secret}, "response": {token}}
	if ip != "" {
		form.Set("remoteip", ip)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%s: %w", g.Scheme, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", g.Scheme, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: siteverify returned %s", g.Scheme, resp.Status)
	}

	var result struct {
		Success    bool     `json:"success"`
		Score      *float64 `json:"score"` // reCAPTCHA v3 only
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("%s: decoding siteverify response: %w", g.Scheme, err)
	}
	if !result.Success {
		return reject(g.Name, "token rejected: %s", strings.Join(result.ErrorCodes, ", "))
	}
	if min := g.Options.MinScore; result.Score != nil && min > 0 && *result.Score < min {
		return reject(g.Name, "score %g is below %g", *result.Score, min)
	}
	return nil
}
