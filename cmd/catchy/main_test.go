package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/catchysh/catchy/internal/auth"
	"github.com/catchysh/catchy/internal/db"
	envvars "github.com/catchysh/catchy/internal/env"
	"github.com/catchysh/catchy/internal/guard"
)

func newTestServer(t *testing.T) (*db.DB, *httptest.Server) {
	t.Helper()

	database, err := db.New(t.Context(), "sqlite", "file:"+t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { database.Close(context.Background()) })
	if err := database.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	srv := httptest.NewUnstartedServer(nil)
	mux, err := newMux(database, config{
		hostname:      "http://" + srv.Listener.Addr().String(),
		sessionSecret: "test",
		autoCreate:    true,
		env:           envvars.Env{Secrets: map[string]string{"HMAC_SECRET": "hmac-secret", "JOBS_KEY": "super-secret-value"}},
	})
	if err != nil {
		t.Fatalf("newMux: %v", err)
	}
	srv.Config.Handler = mux
	srv.Start()
	t.Cleanup(srv.Close)
	return database, srv
}

// apiKey creates a user and returns a fresh API key for them.
func apiKey(t *testing.T, database *db.DB, googleID string) string {
	t.Helper()

	user, err := database.UpsertUser(t.Context(), googleID, googleID+"@example.com", googleID)
	if err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	key, _, err := database.CreateAPIKey(t.Context(), user.ID, "test")
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	return key
}

func call(t *testing.T, srv *httptest.Server, method, path, key, contentType, body string, out any) int {
	t.Helper()

	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: decoding %s: %v", method, path, raw, err)
		}
	}
	return resp.StatusCode
}

type apiHook struct {
	ID      string            `json:"id"`
	Channel string            `json:"channel"`
	Status  string            `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"` // base64 in JSON
	Payload map[string]any    `json:"payload"`
	Events  []struct {
		Kind    string `json:"kind"`
		Actor   string `json:"actor"`
		Message string `json:"message"`
	} `json:"events"`
	FinalizedAt *string `json:"finalized_at"`
}

type apiChannel struct {
	Name   string   `json:"name"`
	Paused bool     `json:"paused"`
	Guards []string `json:"guards"`
	Stats  struct {
		Pending string `json:"pending"` // int64 is a JSON string
		Handled string `json:"handled"`
	} `json:"stats"`
}

func TestEndToEnd(t *testing.T) {
	database, srv := newTestServer(t)
	key := apiKey(t, database, "alice")

	// A browser form and a webhook post to the root without credentials.
	if code := call(t, srv, "POST", "/?channel=contact", "", "application/x-www-form-urlencoded", "email=jane%40example.com&message=Hi", nil); code != 200 {
		t.Fatalf("form hook: %d", code)
	}
	if code := call(t, srv, "POST", "/", "", "application/json", `{"event":"ping"}`, nil); code != 200 {
		t.Fatalf("JSON hook: %d", code)
	}

	var all []apiHook
	if code := call(t, srv, "GET", "/v1/hooks", key, "", "", &all); code != 200 {
		t.Fatalf("ListHooks: %d", code)
	}
	if len(all) != 2 || all[0].Channel != "default" || all[1].Channel != "contact" ||
		string(all[0].Body) != `{"event":"ping"}` || all[0].Payload["event"] != "ping" || all[0].Status != "pending" {
		t.Fatalf("hooks = %+v", all)
	}

	var contact []apiHook
	call(t, srv, "GET", "/v1/hooks?channel=contact", key, "", "", &contact)
	if len(contact) != 1 || contact[0].Payload["email"] != "jane@example.com" {
		t.Fatalf("contact hooks = %+v", contact)
	}

	var page []apiHook
	call(t, srv, "GET", "/v1/hooks?limit=1&after="+all[0].ID, key, "", "", &page)
	if len(page) != 1 || page[0].ID != all[1].ID {
		t.Fatalf("second page = %+v", page)
	}

	// Hooks can be discarded and retried; processing and failing come
	// from attempts, not the API.
	var got apiHook
	if code := call(t, srv, "POST", "/v1/hooks/"+contact[0].ID+"/discard", key, "application/json", `{}`, &got); code != 200 || got.Status != "discarded" || got.FinalizedAt == nil {
		t.Fatalf("discarded hook: %d %+v", code, got)
	}
	if code := call(t, srv, "POST", "/v1/hooks/"+contact[0].ID+"/retry", key, "application/json", `{}`, &got); code != 200 || got.Status != "pending" {
		t.Fatalf("retried hook: %d %+v", code, got)
	}
	// Both are events, by the API key.
	if len(got.Events) != 2 || got.Events[0].Kind != "discarded" || got.Events[1].Kind != "retried" || got.Events[1].Actor != "api:test" {
		t.Fatalf("events = %+v", got.Events)
	}
	if code := call(t, srv, "POST", "/v1/hooks/01m4bdkawf4vkn58kbtxrdqnyg/discard", key, "application/json", `{}`, nil); code != 404 {
		t.Fatalf("DiscardHook on a missing hook: %d, want 404", code)
	}
	for _, verb := range []string{"process", "fail"} {
		if code := call(t, srv, "POST", "/v1/hooks/"+contact[0].ID+"/"+verb, key, "application/json", `{}`, nil); code != 404 && code != 405 {
			t.Fatalf("POST /%s still answers: %d", verb, code)
		}
	}
	if code := call(t, srv, "GET", "/v1/hooks/"+contact[0].ID, key, "", "", &got); code != 200 || got.Status != "pending" {
		t.Fatalf("GetHook: %d %+v", code, got)
	}

	var channels []apiChannel
	call(t, srv, "GET", "/v1/channels", key, "", "", &channels)
	if len(channels) != 2 || channels[0].Name != "contact" || channels[1].Stats.Pending != "1" {
		t.Fatalf("channels = %+v", channels)
	}

	var paused apiChannel
	if code := call(t, srv, "POST", "/v1/channels/contact/pause", key, "application/json", `{}`, &paused); code != 200 || !paused.Paused {
		t.Fatalf("PauseChannel: %d %+v", code, paused)
	}
	if code := call(t, srv, "POST", "/?channel=contact", "", "application/json", `{"a":1}`, nil); code != 503 {
		t.Fatalf("hook to paused channel: %d, want 503", code)
	}
	if code := call(t, srv, "POST", "/v1/channels/contact/resume", key, "application/json", `{}`, &paused); code != 200 || paused.Paused {
		t.Fatalf("ResumeChannel: %d %+v", code, paused)
	}

	// Guards are set up in the dashboard; the API shows them on the channel.
	if _, err := database.CreateGuard(t.Context(), db.Guard{Name: "signer", Type: guard.Signature, Scheme: guard.HMAC, Secret: "HMAC_SECRET",
		Options: `{"header":"X-Catchy-Signature","algorithm":"sha256","encoding":"hex","prefix":"sha256="}`}); err != nil {
		t.Fatal(err)
	}
	database.SetChannelGuards(t.Context(), "signed", []string{"signer"})
	var signed apiChannel
	if code := call(t, srv, "GET", "/v1/channels/signed", key, "", "", &signed); code != 200 || fmt.Sprint(signed.Guards) != "[signer]" {
		t.Fatalf("GetChannel: %d %+v", code, signed)
	}
	if code := call(t, srv, "POST", "/?channel=signed", "", "application/json", `{"a":1}`, nil); code != 403 {
		t.Fatalf("unsigned hook: %d, want 403", code)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/?channel=signed", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Catchy-Signature", guard.Sign("hmac-secret", []byte(`{"a":1}`)))
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("signed hook: %v %v", resp.Status, err)
	}

	if code := call(t, srv, "GET", "/v1/channels/missing", key, "", "", nil); code != 404 {
		t.Fatalf("GetChannel missing: %d, want 404", code)
	}

	if code := call(t, srv, "DELETE", "/v1/hooks/"+all[0].ID, key, "", "", nil); code != 200 {
		t.Fatalf("DeleteHook: %d", code)
	}
	if code := call(t, srv, "DELETE", "/v1/channels/contact", key, "", "", nil); code != 200 {
		t.Fatalf("DeleteChannel: %d", code)
	}
	var left []apiHook
	call(t, srv, "GET", "/v1/hooks", key, "", "", &left)
	if len(left) != 1 || left[0].Channel != "signed" {
		t.Fatalf("hooks left = %+v, want only the signed one", left)
	}
}

func TestAPIRequiresKey(t *testing.T) {
	_, srv := newTestServer(t)
	if code := call(t, srv, "GET", "/v1/hooks", "", "", "", nil); code != 401 {
		t.Fatalf("no key: %d, want 401", code)
	}
	if code := call(t, srv, "GET", "/v1/hooks", "bogus", "", "", nil); code != 401 {
		t.Fatalf("bad key: %d, want 401", code)
	}
}

func TestNamedRoutesWinOverHooks(t *testing.T) {
	_, srv := newTestServer(t)

	if code := call(t, srv, "GET", "/health", "", "", "", nil); code != 200 {
		t.Fatalf("GET /health: %d", code)
	}
	if code := call(t, srv, "GET", "/", "", "", "", nil); code != 200 {
		t.Fatalf("GET / (login page): %d", code)
	}
	if code := call(t, srv, "POST", "/channels/contact/delete", "", "", "", nil); code != 401 {
		t.Fatalf("POST /channels/contact/delete without session: %d, want 401", code)
	}
	if code := call(t, srv, "GET", "/anything", "", "", "", nil); code != 404 {
		t.Fatalf("GET /anything: %d, want 404", code)
	}
	if code := call(t, srv, "GET", "/auth/google/login", "", "", "", nil); code != 307 {
		t.Fatalf("GET /auth/google/login: %d, want 307", code)
	}
}

func TestDashboard(t *testing.T) {
	database, srv := newTestServer(t)
	user, err := database.UpsertUser(t.Context(), "alice", "alice@example.com", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	auth.NewSessionManager("test").SetSession(rec, user.ID)
	cookie := rec.Result().Cookies()[0]

	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(srv.URL)
	jar.SetCookies(u, []*http.Cookie{cookie})
	client := &http.Client{Jar: jar}

	page := func(method, path, form string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(form))
		if form != "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	code, body := page("GET", "/", "")
	if code != 200 || !strings.Contains(body, "No hooks yet") || !strings.Contains(body, `curl -X POST "`+srv.URL+`/?channel=test"`) {
		t.Fatalf("empty hooks page: %d\n%s", code, body)
	}

	call(t, srv, "POST", "/?channel=contact", "", "application/x-www-form-urlencoded", "email=jane%40example.com&message=Hello+%3Cb%3Ethere%3C%2Fb%3E", nil)
	call(t, srv, "POST", "/?channel=newsletter", "", "application/x-www-form-urlencoded", "email=bob%40example.com", nil)
	call(t, srv, "POST", "/?channel=raw", "", "application/xml", "<event>ping</event>", nil)

	// The list shows a line per hook, linking to its page at /{id}.
	contact, _ := database.ListHooks(t.Context(), db.HookFilter{Channel: "contact"}, 1)
	code, body = page("GET", "/", "")
	if code != 200 || !strings.Contains(body, "jane@example.com · Hello &lt;b&gt;there&lt;/b&gt;") || !strings.Contains(body, "bob@example.com") ||
		!strings.Contains(body, "&lt;event&gt;ping&lt;/event&gt;") || !strings.Contains(body, "#newsletter</td>") ||
		!strings.Contains(body, `href="/`+contact[0].ID+`"`) || strings.Contains(body, ">Handle</button>") {
		t.Fatalf("hooks page: %d\n%s", code, body)
	}

	// A hook's page has everything, with actions and links back to its list.
	code, body = page("GET", "/"+contact[0].ID+"?channel=contact", "")
	if code != 200 || !strings.Contains(body, "Hello &lt;b&gt;there&lt;/b&gt;") || !strings.Contains(body, ">Handle</button>") ||
		!strings.Contains(body, "Raw request") || !strings.Contains(body, `href="/?channel=contact"`) || !strings.Contains(body, "· #contact") {
		t.Fatalf("hook page: %d\n%s", code, body)
	}
	for _, path := range []string{"/01zzzzzzzzzzzzzzzzzzzzzzzz", "/not-a-hook", "/favicon.ico"} {
		if code, _ := page("GET", path, ""); code != 404 {
			t.Fatalf("GET %s: %d, want 404", path, code)
		}
	}

	// Newer and older step through the list it was opened from.
	all, _ := database.ListHooks(t.Context(), db.HookFilter{}, 10) // raw, newsletter, contact
	_, body = page("GET", "/"+all[1].ID, "")
	if !strings.Contains(body, `href="/`+all[0].ID+`" rel="prev"`) || !strings.Contains(body, `href="/`+all[2].ID+`" rel="next"`) {
		t.Fatalf("neighbors of the middle hook:\n%s", body)
	}
	_, body = page("GET", "/"+contact[0].ID+"?channel=contact", "")
	if strings.Contains(body, `rel="prev"`) || strings.Contains(body, `rel="next"`) {
		t.Fatalf("the only #contact hook has neighbors:\n%s", body)
	}

	// The hooks feed filtered to one channel.
	code, body = page("GET", "/?channel=contact", "")
	if code != 200 || !strings.Contains(body, "jane@example.com") || strings.Contains(body, "bob@example.com") ||
		!strings.Contains(body, `<option value="contact" selected>`) {
		t.Fatalf("filtered hooks page: %d\n%s", code, body)
	}
	if code, _ := page("GET", "/?channel=missing", ""); code != 404 {
		t.Fatalf("missing channel filter: %d, want 404", code)
	}

	// The Channels tab lists channels with their stats; each has a page.
	code, body = page("GET", "/channels", "")
	if code != 200 || !strings.Contains(body, `href="/channels/newsletter"`) || !strings.Contains(body, `href="/?channel=raw&amp;status=pending"`) {
		t.Fatalf("channels page: %d\n%s", code, body)
	}
	code, body = page("GET", "/channels/contact", "")
	if code != 200 || !strings.Contains(body, srv.URL+"/?channel=contact") || !strings.Contains(body, "Delete channel") ||
		!strings.Contains(body, "Save guards") || !strings.Contains(body, `href="/?channel=contact"`) {
		t.Fatalf("channel page: %d\n%s", code, body)
	}
	if code, _ := page("GET", "/channels/missing", ""); code != 404 {
		t.Fatalf("missing channel page: %d, want 404", code)
	}

	// Mark the newsletter hook handled, then filter by status.
	hooks, _ := database.ListHooks(t.Context(), db.HookFilter{Channel: "newsletter"}, 10)
	page("POST", "/hooks/"+hooks[0].ID+"/handle", "back=%2F%3Fchannel%3Dnewsletter")
	if _, body := page("GET", "/"+hooks[0].ID, ""); !strings.Contains(body, "by alice@example.com") || !strings.Contains(body, ">caught</span>") {
		t.Fatalf("activity on the handled hook's page:\n%s", body)
	}
	if hk, _ := database.GetHook(t.Context(), hooks[0].ID); hk.Status != db.StatusHandled {
		t.Fatalf("status = %q, want handled", hk.Status)
	}
	code, body = page("GET", "/?status=pending", "")
	if code != 200 || strings.Contains(body, "bob@example.com") || !strings.Contains(body, "jane@example.com") {
		t.Fatalf("pending filter: %d\n%s", code, body)
	}
	contactHooks, _ := database.ListHooks(t.Context(), db.HookFilter{Channel: "contact"}, 10)
	database.SetHookStatus(t.Context(), contactHooks[0].ID, db.StatusFailed, "smtp", "<refused>")
	// The list shows it failed; the reason is on the hook's page.
	code, body = page("GET", "/?status=failed", "")
	if code != 200 || !strings.Contains(body, `href="/`+contactHooks[0].ID+`?status=failed"`) || strings.Contains(body, "&lt;refused&gt;") {
		t.Fatalf("failed filter: %d\n%s", code, body)
	}
	if _, body := page("GET", "/"+contactHooks[0].ID, ""); !strings.Contains(body, "smtp: &lt;refused&gt;") || !strings.Contains(body, ">Retry</button>") {
		t.Fatalf("failed hook page:\n%s", body)
	}
	database.SetHookStatus(t.Context(), contactHooks[0].ID, db.StatusPending, "", "")

	if _, body := page("GET", "/?status=discarded&channel=contact", ""); !strings.Contains(body, "No discarded hooks in") {
		t.Fatalf("empty filtered page: %s", body)
	}
	code, body = page("GET", "/?status=handled", "")
	if code != 200 || !strings.Contains(body, "bob@example.com") || strings.Contains(body, "jane@example.com") {
		t.Fatalf("handled filter: %d\n%s", code, body)
	}

	code, body = page("POST", "/channels/contact/pause", "")
	if code != 200 || !strings.Contains(body, "Paused since") || !strings.Contains(body, ">Resume</button>") {
		t.Fatalf("paused channel page: %d\n%s", code, body)
	}
	page("POST", "/channels/contact/resume", "")
	if c, _ := database.GetChannel(t.Context(), "contact"); c.Paused() {
		t.Fatal("channel still paused after resume")
	}

	// Create a guard on the Guards page, then attach it to a new channel.
	code, body = page("POST", "/guards", "name=jobs-key&type=signature&scheme=hmac&header=X-Catchy-Signature&algorithm=sha256&encoding=hex&prefix=sha256%3D&secret=JOBS_KEY")
	if code != 200 || !strings.Contains(body, "jobs-key") || !strings.Contains(body, "signature · hmac · X-Catchy-Signature · sha256 hex") ||
		!strings.Contains(body, ">JOBS_KEY</code>") || strings.Contains(body, "super-secret-value") {
		t.Fatalf("guards page after create: %d\n%s", code, body)
	}
	if code, body := page("POST", "/guards", "name=bad&type=signature&scheme=hmac&secret=%7B%7B.Secrets.JOBS_KEY%7D%7D"); code != 422 || !strings.Contains(body, "Secret names are") {
		t.Fatalf("guard with a bad secret name: %d\n%s", code, body)
	}

	// A guard can use a secret that isn't set yet; every page then says so.
	code, body = page("POST", "/guards", "name=unset&type=signature&scheme=hmac&secret=NOPE")
	if code != 200 || !strings.Contains(body, "Not set: add CATCHY_SECRET_NOPE") || !strings.Contains(body, "1 secret is used but not set") ||
		!strings.Contains(body, "(guard unset)") {
		t.Fatalf("guard with an unset secret: %d\n%s", code, body)
	}
	if _, body := page("GET", "/channels", ""); !strings.Contains(body, "add <code>CATCHY_SECRET_NOPE</code>") {
		t.Fatalf("no banner on another page:\n%s", body)
	}
	page("POST", "/guards/unset/delete", "")
	if _, body := page("GET", "/channels", ""); strings.Contains(body, "used but not set") {
		t.Fatalf("banner after deleting the guard:\n%s", body)
	}
	if code, body := page("POST", "/guards", "name=bad&type=signature&scheme=hmac"); !strings.Contains(body, "needs the signing secret") {
		t.Fatalf("guard without secret: %d\n%s", code, body)
	}
	code, body = page("POST", "/channels", "name=webhooks")
	if code != 200 || !strings.Contains(body, `value="jobs-key"`) || !strings.Contains(body, "Save guards") {
		t.Fatalf("new channel page: %d\n%s", code, body)
	}
	page("POST", "/channels/webhooks/guards", "guard=honeypot&guard=jobs-key")
	if c, _ := database.GetChannel(t.Context(), "webhooks"); fmt.Sprint(c.Guards) != "[honeypot jobs-key]" {
		t.Fatalf("guards = %v", c.Guards)
	}
	code, body = page("GET", "/channels/webhooks", "")
	if !strings.Contains(body, "X-Catchy-Signature: sha256=$SIG") {
		t.Fatalf("HMAC curl snippet missing: %d\n%s", code, body)
	}

	// Handlers: create one, open its page, edit it, and see it in the list.
	code, body = page("POST", "/handlers", "name=fwd&type=http&method=POST&url=https%3A%2F%2Fexample.com%2Fhooks")
	if code != 200 || !strings.Contains(body, `href="/handlers/fwd"`) || !strings.Contains(body, "POST example.com · forward") || !strings.Contains(body, ">never<") {
		t.Fatalf("handlers list: %d\n%s", code, body)
	}
	code, body = page("GET", "/handlers/fwd", "")
	if code != 200 || !strings.Contains(body, `value="https://example.com/hooks"`) || !strings.Contains(body, "readonly") || !strings.Contains(body, ">Save</button>") {
		t.Fatalf("handler page: %d\n%s", code, body)
	}
	code, body = page("POST", "/handlers/fwd", "type=script&script=const+x+%3D+%3B")
	if code != 422 || !strings.Contains(body, "SyntaxError") || !strings.Contains(body, "const x = ;") {
		t.Fatalf("saving a broken script: %d\n%s", code, body)
	}
	code, body = page("POST", "/handlers/fwd", "type=script&script=console.log(hook.id)")
	if code != 200 || !strings.Contains(body, "Saved.") {
		t.Fatalf("saving a script: %d\n%s", code, body)
	}
	if h, _ := database.GetHandler(t.Context(), "fwd"); h.Type != "script" || !strings.Contains(h.Options, "console.log(hook.id)") {
		t.Fatalf("saved handler = %+v", h)
	}
	if _, body := page("GET", "/handlers", ""); !strings.Contains(body, ">script</span>") || !strings.Contains(body, "1 line") {
		t.Fatalf("list after editing:\n%s", body)
	}
	if code, _ := page("GET", "/handlers/missing", ""); code != 404 {
		t.Fatalf("missing handler page: %d, want 404", code)
	}
	page("POST", "/handlers/fwd/delete", "")
	if _, err := database.GetHandler(t.Context(), "fwd"); err == nil {
		t.Fatal("handler still there after delete")
	}

	// A guard's page shows its settings; saving changes them.
	code, body = page("GET", "/guards/jobs-key", "")
	if code != 200 || !strings.Contains(body, `value="X-Catchy-Signature"`) || !strings.Contains(body, "readonly") || !strings.Contains(body, "#webhooks") {
		t.Fatalf("guard page: %d\n%s", code, body)
	}
	code, body = page("POST", "/guards/jobs-key", "type=signature&scheme=hmac&header=X-Sig&algorithm=sha256&encoding=hex&secret=bad-name")
	if code != 422 || !strings.Contains(body, "Secret names are") || !strings.Contains(body, `value="X-Sig"`) {
		t.Fatalf("saving a bad guard: %d\n%s", code, body)
	}
	code, body = page("POST", "/guards/jobs-key", "type=signature&scheme=hmac&header=X-Sig&algorithm=sha256&encoding=hex&secret=JOBS_KEY")
	if code != 200 || !strings.Contains(body, "Saved.") {
		t.Fatalf("saving a guard: %d\n%s", code, body)
	}
	if g, _ := database.GetGuard(t.Context(), "jobs-key"); !strings.Contains(g.Options, "X-Sig") {
		t.Fatalf("saved guard = %+v", g)
	}

	// Try to delete while attached, detach, delete.
	if _, body := page("POST", "/guards/jobs-key/delete", ""); !strings.Contains(body, "Detach it from its channels") {
		t.Fatalf("deleting an attached guard: %s", body)
	}
	page("POST", "/channels/webhooks/guards", "guard=honeypot")
	page("POST", "/guards/jobs-key/delete", "")
	if _, err := database.GetGuard(t.Context(), "jobs-key"); err == nil {
		t.Fatal("guard not deleted")
	}
	if code, body := page("POST", "/channels", "name=Bad--Name"); !strings.Contains(body, "Channel names are") {
		t.Fatalf("invalid channel name: %d", code)
	}

	page("POST", "/hooks/"+hooks[0].ID+"/delete", "back=%2F%2Fevil.example")
	if _, err := database.GetHook(t.Context(), hooks[0].ID); err == nil {
		t.Fatalf("hook not deleted")
	}

	if code, _ := page("GET", "/keys", ""); code != 200 {
		t.Fatalf("keys page: %d", code)
	}

	page("POST", "/channels/contact/delete", "")
	if _, err := database.GetChannel(t.Context(), "contact"); err == nil {
		t.Fatal("channel not deleted")
	}
}
