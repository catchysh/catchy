package hook

import (
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/catchysh/catchy/internal/db"
	"github.com/catchysh/catchy/internal/env"
	"github.com/catchysh/catchy/internal/guard"
	"github.com/catchysh/catchy/internal/payload"
)

// newTestServer returns a database and a handler serving hooks at /.
func newTestServer(t *testing.T) (*db.DB, http.Handler) {
	t.Helper()

	database, err := db.New(t.Context(), "sqlite", "file:"+t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { database.Close(context.Background()) })
	if err := database.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	h := NewHandler(database, &guard.Checker{}, testEnv, true, false)
	mux := http.NewServeMux()
	mux.Handle("POST /{$}", h)
	mux.Handle("OPTIONS /{$}", h)
	return database, mux
}

// hooks returns the hooks in channel, newest first; empty means all channels.
func hooks(t *testing.T, database *db.DB, channel string) []db.Hook {
	t.Helper()

	stored, err := database.ListHooks(t.Context(), db.HookFilter{Channel: channel}, 100)
	if err != nil {
		t.Fatalf("ListHooks: %v", err)
	}
	return stored
}

func fieldsOf(h db.Hook) map[string]any {
	return payload.Decode(h.ContentType, h.Body)
}

func do(h http.Handler, method, path, contentType, body string, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestFormHook(t *testing.T) {
	database, h := newTestServer(t)

	form := url.Values{"email": {"jane@example.com"}, "message": {"Hi!\nThere"}, "topic": {"a", "b"}}
	rec := do(h, http.MethodPost, "/", "application/x-www-form-urlencoded", form.Encode(),
		"Accept", "text/html", "Referer", "https://example.com/contact", "User-Agent", "test-agent", "Cookie", "catchy_session=secret")

	// Even a browser form gets JSON: the page shows its own thank-you.
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" || !strings.Contains(rec.Body.String(), `{"id":"`) {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}

	stored := hooks(t, database, db.DefaultChannel)
	if len(stored) != 1 {
		t.Fatalf("got %d hooks, want 1", len(stored))
	}
	hk := stored[0]
	data := fieldsOf(hk)
	if data["email"] != "jane@example.com" || data["message"] != "Hi!\nThere" {
		t.Fatalf("payload = %v", data)
	}
	if topics, _ := data["topic"].([]any); len(topics) != 2 {
		t.Fatalf("repeated field topic = %v, want two values", data["topic"])
	}
	if string(hk.Body) != form.Encode() || hk.Method != "POST" || hk.Status != db.StatusPending {
		t.Fatalf("hook = %+v", hk)
	}
	if hk.Headers["Referer"] != "https://example.com/contact" || hk.Headers["User-Agent"] != "test-agent" || hk.IP == "" {
		t.Fatalf("headers = %v, ip = %q", hk.Headers, hk.IP)
	}
	if _, ok := hk.Headers["Cookie"]; ok {
		t.Fatal("cookie header stored")
	}
}

func TestMultipartHook(t *testing.T) {
	database, h := newTestServer(t)

	var body strings.Builder
	mw := multipart.NewWriter(&body)
	mw.WriteField("name", "Jane")
	fw, _ := mw.CreateFormFile("attachment", "a.txt")
	fw.Write([]byte("ignored"))
	mw.Close()

	rec := do(h, http.MethodPost, "/", mw.FormDataContentType(), body.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	stored := hooks(t, database, "")
	if data := fieldsOf(stored[0]); len(stored) != 1 || data["name"] != "Jane" || data["attachment"] != nil {
		t.Fatalf("payload = %v", data)
	}
	if string(stored[0].Body) != body.String() {
		t.Fatal("raw multipart body not kept")
	}
}

func TestJSONHook(t *testing.T) {
	database, h := newTestServer(t)

	body := `{"type":"invoice.paid",  "amount":1.50,"tags":["x"]}`
	rec := do(h, http.MethodPost, "/?channel=stripe&source=test", "application/json; charset=utf-8", body, "Stripe-Signature", "t=1,v1=abc")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.ID) != 26 || strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("response = %s", rec.Body)
	}

	hk, err := database.GetHook(t.Context(), resp.ID)
	if err != nil {
		t.Fatalf("GetHook: %v", err)
	}
	// The body is kept byte for byte, e.g. for signature checks.
	if string(hk.Body) != body || hk.Headers["Stripe-Signature"] != "t=1,v1=abc" || hk.Query != "channel=stripe&source=test" ||
		hk.ContentType != "application/json; charset=utf-8" || hk.Channel != "stripe" {
		t.Fatalf("hook = %+v", hk)
	}
	if data := fieldsOf(*hk); data["type"] != "invoice.paid" || data["amount"] != json.Number("1.50") {
		t.Fatalf("payload = %v", data)
	}
}

func TestAnyBodyIsCaught(t *testing.T) {
	database, h := newTestServer(t)

	cases := []struct {
		name        string
		contentType string
		body        string
	}{
		{"XML", "application/xml", "<event>ping</event>"},
		{"plain text", "text/plain", "hello"},
		{"JSON array", "application/json", `["a"]`},
		{"invalid JSON", "application/json", `{"a":`},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(h, http.MethodPost, "/?channel=raw", tc.contentType, tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
			}
			hk := hooks(t, database, "raw")[0]
			if string(hk.Body) != tc.body || fieldsOf(hk) != nil {
				t.Fatalf("hook body %q payload %v, want body %q and no payload", hk.Body, fieldsOf(hk), tc.body)
			}
		})
	}
}

func TestHoneypotDropsHook(t *testing.T) {
	database, h := newTestServer(t)
	database.SetChannelGuards(t.Context(), "contact", []string{"honeypot"})
	database.SetChannelGuards(t.Context(), db.DefaultChannel, []string{"honeypot"})

	rec := do(h, http.MethodPost, "/?channel=contact", "application/x-www-form-urlencoded", "email=a%40b.c&_gotcha=spam")
	// The bot gets a normal-looking ID, which isn't stored.
	var resp struct {
		ID string `json:"id"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || len(resp.ID) != 26 {
		t.Fatalf("status = %d, want a normal success", rec.Code)
	}
	if n := len(hooks(t, database, "")); n != 0 {
		t.Fatalf("stored %d hooks, want 0", n)
	}

	// An empty honeypot is a real visitor; the field isn't kept in the payload.
	do(h, http.MethodPost, "/", "application/x-www-form-urlencoded", "email=a%40b.c&_gotcha=")
	stored := hooks(t, database, "")
	if len(stored) != 1 {
		t.Fatalf("stored %d hooks, want 1", len(stored))
	}
	if _, ok := fieldsOf(stored[0])[payload.HoneypotField]; ok {
		t.Fatalf("honeypot field in payload: %v", fieldsOf(stored[0]))
	}
}

func TestRejectedHooks(t *testing.T) {
	database, h := newTestServer(t)

	cases := []struct {
		name string
		path string
		body string
		want int
	}{
		{"invalid channel", "/?channel=-bad", `{}`, http.StatusBadRequest},
		{"double separator", "/?channel=a--b", `{}`, http.StatusBadRequest},
		{"long channel", "/?channel=" + strings.Repeat("a", 65), `{}`, http.StatusBadRequest},
		{"too large", "/", strings.Repeat("x", MaxBodySize+1), http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(h, http.MethodPost, tc.path, "application/json", tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body)
			}
		})
	}
	if n := len(hooks(t, database, "")); n != 0 {
		t.Fatalf("stored %d hooks, want 0", n)
	}
}

func TestChannels(t *testing.T) {
	database, h := newTestServer(t)

	do(h, http.MethodPost, "/?channel=contact", "application/json", `{"n":1}`)
	do(h, http.MethodPost, "/?channel=Contact", "application/json", `{"n":2}`)
	do(h, http.MethodPost, "/?channel=newsletter", "application/x-www-form-urlencoded", "email=a%40b.c")
	do(h, http.MethodPost, "/", "application/json", `{"n":3}`)

	if n := len(hooks(t, database, "contact")); n != 2 {
		t.Fatalf("contact has %d hooks, want 2 (names are lowercased)", n)
	}
	if n := len(hooks(t, database, "newsletter")); n != 1 {
		t.Fatalf("newsletter has %d hooks, want 1", n)
	}
	if n := len(hooks(t, database, db.DefaultChannel)); n != 1 {
		t.Fatalf("default has %d hooks, want 1", n)
	}
}

func TestCORSPreflight(t *testing.T) {
	_, h := newTestServer(t)

	rec := do(h, http.MethodOptions, "/", "", "",
		"Origin", "https://example.com", "Access-Control-Request-Method", "POST", "Access-Control-Request-Headers", "content-type, x-custom")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" || rec.Header().Get("Access-Control-Allow-Headers") != "content-type, x-custom" {
		t.Fatalf("headers = %v", rec.Header())
	}
}

func TestPausedChannelRefusesHooks(t *testing.T) {
	database, h := newTestServer(t)
	do(h, http.MethodPost, "/?channel=stripe", "application/json", `{"n":1}`)
	if _, err := database.SetChannelPaused(t.Context(), "stripe", true); err != nil {
		t.Fatal(err)
	}

	rec := do(h, http.MethodPost, "/?channel=stripe", "application/json", `{"n":2}`)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("status = %d, Retry-After = %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if n := len(hooks(t, database, "stripe")); n != 1 {
		t.Fatalf("stripe has %d hooks, want 1", n)
	}

	// Other channels are unaffected, and resuming lets hooks in again.
	if rec := do(h, http.MethodPost, "/?channel=github", "application/json", `{}`); rec.Code != http.StatusOK {
		t.Fatalf("github: status = %d", rec.Code)
	}
	database.SetChannelPaused(t.Context(), "stripe", false)
	if rec := do(h, http.MethodPost, "/?channel=stripe", "application/json", `{"n":3}`); rec.Code != http.StatusOK {
		t.Fatalf("after resume: status = %d", rec.Code)
	}
}

func TestChannelGuards(t *testing.T) {
	database, h := newTestServer(t)
	github := `{"header":"X-Hub-Signature-256","algorithm":"sha256","encoding":"hex","prefix":"sha256="}`
	if _, err := database.CreateGuard(t.Context(), db.Guard{Name: "gh", Type: guard.Signature, Scheme: guard.HMAC, Options: github, Secret: "GH_SECRET"}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SetChannelGuards(t.Context(), "github", []string{"gh"}); err != nil {
		t.Fatal(err)
	}
	body := `{"ref":"refs/heads/main"}`

	rec := do(h, http.MethodPost, "/?channel=github", "application/json", body, "X-Hub-Signature-256", "sha256=00")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "verification failed") {
		t.Fatalf("bad signature: status = %d, body %s", rec.Code, rec.Body)
	}
	if n := len(hooks(t, database, "github")); n != 0 {
		t.Fatalf("stored %d hooks after a bad signature", n)
	}

	rec = do(h, http.MethodPost, "/?channel=github", "application/json", body, "X-Hub-Signature-256", guard.Sign("gh-secret", []byte(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("good signature: status = %d, body %s", rec.Code, rec.Body)
	}
	if n := len(hooks(t, database, "github")); n != 1 {
		t.Fatalf("stored %d hooks, want 1", n)
	}

	// A channel with no guards stores even a filled honeypot.
	database.SetChannelGuards(t.Context(), "open", nil)
	do(h, http.MethodPost, "/?channel=open", "application/x-www-form-urlencoded", "a=b&_gotcha=x")
	if n := len(hooks(t, database, "open")); n != 1 {
		t.Fatalf("open channel stored %d hooks, want 1", n)
	}
}

func TestTokenGuard(t *testing.T) {
	database, h := newTestServer(t)
	database.CreateGuard(t.Context(), db.Guard{Name: "bearer", Type: guard.Token, Options: `{"header":"Authorization","prefix":"Bearer "}`, Secret: "TOKEN"})
	database.SetChannelGuards(t.Context(), "ci", []string{"bearer"})

	if rec := do(h, http.MethodPost, "/?channel=ci", "application/json", `{}`, "Authorization", "Bearer nope"); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong token: status = %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/?channel=ci", "application/json", `{}`, "Authorization", "Bearer tok-123"); rec.Code != http.StatusOK {
		t.Fatalf("right token: status = %d, body %s", rec.Code, rec.Body)
	}
}

var testEnv = env.Env{Secrets: map[string]string{"GH_SECRET": "gh-secret", "TOKEN": "tok-123", "CI_TOKEN": "tok-env"}}

func TestGuardSecretFromEnv(t *testing.T) {
	database, h := newTestServer(t)
	database.CreateGuard(t.Context(), db.Guard{Name: "bearer", Type: guard.Token, Options: `{"header":"Authorization","prefix":"Bearer "}`, Secret: "CI_TOKEN"})
	database.CreateGuard(t.Context(), db.Guard{Name: "unset", Type: guard.Token, Options: `{"header":"X-Token"}`, Secret: "NOPE"})
	database.SetChannelGuards(t.Context(), "ci", []string{"bearer"})
	database.SetChannelGuards(t.Context(), "broken", []string{"unset"})

	if rec := do(h, http.MethodPost, "/?channel=ci", "application/json", `{}`, "Authorization", "Bearer CI_TOKEN"); rec.Code != http.StatusForbidden {
		t.Fatalf("the secret's name as the token: status = %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/?channel=ci", "application/json", `{}`, "Authorization", "Bearer tok-env"); rec.Code != http.StatusOK {
		t.Fatalf("env token: status = %d, body %s", rec.Code, rec.Body)
	}
	// A reference to an unset secret fails closed.
	if rec := do(h, http.MethodPost, "/?channel=broken", "application/json", `{}`, "X-Token", ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("unset env secret: status = %d", rec.Code)
	}
}

func TestAutoCreateOff(t *testing.T) {
	database, _ := newTestServer(t)
	h := NewHandler(database, &guard.Checker{}, testEnv, false, false)
	database.EnsureChannel(t.Context(), "known")

	if rec := do(h, http.MethodPost, "/?channel=unknown", "application/json", `{}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown channel: status = %d", rec.Code)
	}
	if _, err := database.GetChannel(t.Context(), "unknown"); err == nil {
		t.Fatal("a hook created a channel with auto-create off")
	}
	if rec := do(h, http.MethodPost, "/?channel=known", "application/json", `{}`); rec.Code != http.StatusOK {
		t.Fatalf("known channel: status = %d", rec.Code)
	}
}
