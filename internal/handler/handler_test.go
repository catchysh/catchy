package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/catchysh/catchy/internal/db"
	"github.com/catchysh/catchy/internal/env"
	"github.com/catchysh/catchy/internal/guard"
)

// testEnv has the secrets the presets use.
var testEnv = env.Env{Secrets: map[string]string{
	"RESEND_API_KEY":         "re_key",
	"SLACK_WEBHOOK_URL":      "https://hooks.slack.com/services/T/B/X",
	"DISCORD_WEBHOOK_URL":    "https://discord.com/api/webhooks/1/x",
	"WEBHOOK_SIGNING_SECRET": "sig-secret",
}}

func TestValidate(t *testing.T) {
	u := "https://example.com/hook"
	cases := []struct {
		name string
		opts Options
		ok   bool
	}{
		{"forward", Options{URL: u}, true},
		{"bad url", Options{URL: "ftp://example.com"}, false},
		{"no url", Options{}, false},
		{"url from a secret", Options{URL: "{{.Secrets.SLACK_WEBHOOK_URL}}"}, true},
		{"url from a secret that isn't set yet", Options{URL: "{{.Secrets.NOPE}}"}, true},
		{"url that isn't one once filled in", Options{URL: "{{.Secrets.RESEND_API_KEY}}"}, false},
		{"url from the hook", Options{URL: "https://{{.Payload.host}}/x"}, false},
		{"url from vars", Options{URL: "https://example.com/{{.Vars.path}}"}, true},
		{"bad method", Options{URL: u, Method: "GET"}, false},
		{"signed", Options{URL: u, SignWith: "WEBHOOK_SIGNING_SECRET"}, true},
		{"signed with a secret that isn't set yet", Options{URL: u, SignWith: "NOPE"}, true},
		{"signed with a bad name", Options{URL: u, SignWith: "no-pe"}, false},
		{"secret header", Options{URL: u, Headers: "Authorization: Bearer {{.Secrets.RESEND_API_KEY}}"}, true},
		{"header with a secret that isn't set yet", Options{URL: u, Headers: "Authorization: Bearer {{.Secrets.NOPE}}"}, true},
		{"all secrets", Options{URL: u, Body: `{"s": {{json .Secrets}}}`}, false},
		{"header without colon", Options{URL: u, Headers: "Authorization Bearer x"}, false},
		{"bad header template", Options{URL: u, Headers: "X-Token: {{.Nope"}, false},
		{"bad body template", Options{URL: u, Body: "{{.Channel"}, false},
		{"body that isn't JSON", Options{URL: u, Body: `{"text": {{.Text}}}`}, false},
		{"body that is JSON", Options{URL: u, Body: `{"text": {{json .Text}}}`}, true},
		{"body with plain placeholders", Options{URL: u, Body: `{"text": "Hi {{.Payload.name}}: {{.Text}}"}`}, true},
		{"non-JSON body with its content type", Options{URL: u, Body: "hook {{.ID}}", ContentType: "text/plain"}, true},
		{"recipient from a field", Options{URL: u, Body: `{"to": ["{{.Payload.email}}"]}`}, false},
		{"recipient from a nested field", Options{URL: u, Body: `{"cc": "{{.Payload.a.b}}"}`}, false},
		{"recipient from the text", Options{URL: u, Body: `{"from": "{{.Text}}"}`}, false},
		{"recipient from the payload", Options{URL: u, Body: `{"bcc": {{json .Payload}}}`}, false},
		{"recipient from field names", Options{URL: u, Body: `{"to": "{{range $k, $v := .Payload}}{{$k}}{{end}}"}`}, false},
		{"recipient defaulting to a field", Options{URL: u, Body: `{"to": "{{or .Vars.to .Payload.email}}"}`}, false},
		{"recipient from vars", Options{URL: u, Body: `{"to": ["{{or .Vars.to "team@example.com"}}"], "reply_to": "{{.Payload.email}}"}`}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(HTTP, tc.opts, testEnv)
			if (err == nil) != tc.ok {
				t.Fatalf("Validate = %v, want ok %v", err, tc.ok)
			}
		})
	}
	if _, err := Validate("smtp", Options{URL: u}, testEnv); err == nil {
		t.Fatal("accepted an unknown type")
	}
}

func TestValidateDefaults(t *testing.T) {
	o, err := Validate(HTTP, Options{URL: " {{.Secrets.SLACK_WEBHOOK_URL}} ", Body: `{"a":1}`}, testEnv)
	if err != nil {
		t.Fatal(err)
	}
	if o.Method != "POST" || o.ContentType != "application/json" || o.URL != "{{.Secrets.SLACK_WEBHOOK_URL}}" {
		t.Fatalf("options = %+v", o)
	}
	for _, tc := range []struct {
		o    Options
		want string
	}{
		{Options{Method: "POST", URL: "https://x.dev/hooks", SignWith: "S"}, "http · POST x.dev · forward · signed"},
		{Options{Method: "POST", URL: "{{.Secrets.SLACK_WEBHOOK_URL}}", Body: "{}"}, "http · POST {{.Secrets.SLACK_WEBHOOK_URL}}"},
	} {
		if got := Describe(HTTP, tc.o); got != tc.want {
			t.Errorf("Describe = %q, want %q", got, tc.want)
		}
	}
	got := SecretsUsed(Options{URL: "{{.Secrets.A}}", Headers: "X: {{.Secrets.B}} {{ .Secrets.A }}", SignWith: "C"})
	if strings.Join(got, ",") != "A,B,C" {
		t.Fatalf("SecretsUsed = %v", got)
	}
}

func TestPresetsAreValid(t *testing.T) {
	for _, p := range Presets {
		o := p.Options
		if o.URL == "" {
			o.URL = "https://example.com/hooks"
		}
		if _, err := Validate(p.Type, o, testEnv); err != nil {
			t.Errorf("preset %s: %v", p.Name, err)
		}
	}
}

func testHook() db.Hook {
	return db.Hook{
		ID: "01hook", Channel: "contact", CreatedAt: time.Now(),
		ContentType: "application/x-www-form-urlencoded",
		Body:        []byte(`email=jane%40example.com&message=Hi+%22there%22%0Aline+2&_website=`),
	}
}

func TestSlackBodyIsValidJSON(t *testing.T) {
	data := newData(testHook(), "https://catchy.test")
	out, err := renderBody(slackBody, "application/json", data)
	if err != nil {
		t.Fatal(err)
	}
	var msg struct{ Text string }
	if err := json.Unmarshal([]byte(out), &msg); err != nil {
		t.Fatalf("not JSON: %s: %v", out, err)
	}
	want := "New hook in #contact\n\nemail: jane@example.com\nmessage: Hi \"there\"\nline 2"
	if msg.Text != want {
		t.Fatalf("text = %q, want %q", msg.Text, want)
	}
	if data.URL != "https://catchy.test/01hook" {
		t.Fatalf("URL = %q", data.URL)
	}
}

// capture records requests sent to a test server.
type capture struct {
	mu     sync.Mutex
	method string
	header http.Header
	body   []byte
	status int // response status; 0 means 200
}

func (c *capture) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.method, c.header = r.Method, r.Header.Clone()
		c.body, _ = io.ReadAll(r.Body)
		if c.status != 0 {
			w.WriteHeader(c.status)
			fmt.Fprint(w, `{"message":"nope"}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func preset(name string) Preset {
	for _, p := range Presets {
		if p.Name == name {
			return p
		}
	}
	panic("no preset " + name)
}

func TestResendPreset(t *testing.T) {
	var c capture
	srv := c.server(t)
	p := preset("resend")
	o, err := Validate(HTTP, p.Options, testEnv)
	if err != nil {
		t.Fatal(err)
	}
	o.URL = srv.URL
	s := &Runner{Dashboard: "https://catchy.test", Env: testEnv}
	if _, err := s.Run(t.Context(), db.Handler{Type: HTTP, Options: o.JSON()}, testHook()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	var msg struct {
		From    string   `json:"from"`
		To      []string `json:"to"`
		ReplyTo string   `json:"reply_to"`
		Subject string   `json:"subject"`
		Text    string   `json:"text"`
	}
	if err := json.Unmarshal(c.body, &msg); err != nil {
		t.Fatalf("not JSON: %s", c.body)
	}
	if c.header.Get("Authorization") != "Bearer re_key" || c.header.Get("Content-Type") != "application/json" ||
		msg.ReplyTo != "jane@example.com" || msg.Subject != "New hook in #contact" || len(msg.To) != 1 {
		t.Fatalf("request: %s %v", c.body, c.header)
	}
	if !strings.Contains(msg.Text, "email: jane@example.com") || strings.Contains(msg.Text, "_website") ||
		!strings.HasSuffix(msg.Text, "https://catchy.test/01hook") {
		t.Fatalf("text = %q", msg.Text)
	}

	// Without an email field there's no reply_to, and the body is still JSON.
	h := testHook()
	h.ContentType, h.Body = "application/json", []byte(`{"event":"ping"}`)
	if _, err := s.Run(t.Context(), db.Handler{Type: HTTP, Options: o.JSON()}, h); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(c.body) || strings.Contains(string(c.body), "reply_to") {
		t.Fatalf("body = %s", c.body)
	}

	// A provider error comes back with its message.
	c.status = http.StatusUnprocessableEntity
	_, err = s.Run(t.Context(), db.Handler{Type: HTTP, Options: o.JSON()}, testHook())
	if err == nil || !strings.Contains(err.Error(), "HTTP 422") || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("err = %v", err)
	}
}

func TestSendHTTP(t *testing.T) {
	var c capture
	srv := c.server(t)
	s := &Runner{Env: testEnv}
	h := testHook()

	// Forwarding sends the hook as received, signed when asked.
	o, _ := Validate(HTTP, Options{URL: srv.URL, SignWith: "WEBHOOK_SIGNING_SECRET", Headers: "X-Env: prod"}, testEnv)
	if _, err := s.Run(t.Context(), db.Handler{Type: HTTP, Options: o.JSON()}, h); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if string(c.body) != string(h.Body) || c.header.Get("Content-Type") != h.ContentType ||
		c.header.Get("X-Catchy-Hook-Id") != "01hook" || c.header.Get("X-Env") != "prod" {
		t.Fatalf("forwarded %q with %v", c.body, c.header)
	}
	// The signature is what an hmac guard checks.
	if c.header.Get(SignatureHeader) != guard.Sign("sig-secret", h.Body) {
		t.Fatalf("signature = %q", c.header.Get(SignatureHeader))
	}

	// A templated body is sent instead, with its content type.
	o, _ = Validate(HTTP, Options{Method: "PUT", URL: srv.URL, Body: discordBody}, testEnv)
	if _, err := s.Run(t.Context(), db.Handler{Type: HTTP, Options: o.JSON()}, h); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if c.method != "PUT" || c.header.Get("Content-Type") != "application/json" || !strings.Contains(string(c.body), `"content": "New hook in #contact`) {
		t.Fatalf("templated %s %q %v", c.method, c.body, c.header)
	}
}

func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.New(t.Context(), "sqlite", "file:"+t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close(context.Background()) })
	if err := database.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	return database
}

func TestWorker(t *testing.T) {
	database := newTestDB(t)
	var c capture
	srv := c.server(t)
	o, _ := Validate(HTTP, Options{URL: srv.URL}, testEnv)
	if _, err := database.CreateHandler(t.Context(), db.Handler{Name: "fwd", Type: HTTP, Options: o.JSON()}); err != nil {
		t.Fatal(err)
	}
	database.SetChannelHandlers(t.Context(), "contact", []string{"fwd"})

	old := Backoff
	Backoff = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { Backoff = old })
	w := &Worker{DB: database, Runner: &Runner{}}

	catch := func() string {
		h, err := database.CreateHook(t.Context(), db.Hook{Channel: "contact", Method: "POST", ContentType: "application/json", Body: []byte(`{"a":1}`)})
		if err != nil {
			t.Fatal(err)
		}
		if n, err := database.EnqueueAttempts(t.Context(), h.ID, "contact"); err != nil || n != 1 {
			t.Fatalf("EnqueueAttempts = %d, %v", n, err)
		}
		return h.ID
	}
	run := func() {
		time.Sleep(5 * time.Millisecond)
		if err := w.RunOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	// status returns a hook's status and its tries, oldest first.
	status := func(id string) (string, []db.Attempt) {
		h, _ := database.GetHook(t.Context(), id)
		dls, _ := database.HookAttempts(t.Context(), []string{id})
		return h.Status, dls[id]
	}

	// Succeeded: the hook becomes handled.
	ok := catch()
	run()
	if st, tries := status(ok); st != db.StatusHandled || len(tries) != 1 || tries[0].Status != db.AttemptSucceeded ||
		tries[0].HTTPStatus != 200 || tries[0].Number != 1 || tries[0].FinishedAt == nil {
		t.Fatalf("after success: hook %s, tries %+v", st, tries)
	}
	if string(c.body) != `{"a":1}` {
		t.Fatalf("forwarded %q", c.body)
	}

	// Failing: each try is a row; retried per Backoff, then given up, and
	// the hook fails.
	c.status = http.StatusInternalServerError
	bad := catch()
	run()
	if st, tries := status(bad); st != db.StatusPending || len(tries) != 2 || tries[0].Status != db.AttemptFailed ||
		tries[0].HTTPStatus != 500 || !strings.Contains(tries[0].Error, "HTTP 500") || tries[1].Status != db.AttemptPending || tries[1].Number != 2 {
		t.Fatalf("after first failure: hook %s, tries %+v", st, tries)
	}
	run()
	run()
	st, tries := status(bad)
	if st != db.StatusFailed || len(tries) != 3 || tries[2].Status != db.AttemptFailed || tries[2].Number != 3 {
		t.Fatalf("after giving up: hook %s, tries %+v", st, tries)
	}
	if events, _ := database.HookEvents(t.Context(), []string{bad}); len(events[bad]) != 1 || events[bad][0].Kind != db.EventFailed ||
		events[bad][0].Actor != "fwd" || !strings.HasPrefix(events[bad][0].Message, "HTTP 500") {
		t.Fatalf("events = %+v", events[bad])
	}

	// Retrying the hook tries again from attempt 1; now it goes through.
	c.status = 0
	if _, err := database.SetHookStatus(t.Context(), bad, db.StatusPending, "", ""); err != nil {
		t.Fatal(err)
	}
	run()
	if st, tries := status(bad); st != db.StatusHandled || len(tries) != 4 || tries[3].Status != db.AttemptSucceeded || tries[3].Number != 1 {
		t.Fatalf("after retry: hook %s, tries %+v", st, tries)
	}

	// Discarding a hook cancels its queued attempts, and an attempt that was
	// already running doesn't change its status or retry.
	c.status = http.StatusInternalServerError
	dropped := catch()
	run()
	if st, tries := status(dropped); st != db.StatusPending || len(tries) != 2 {
		t.Fatalf("before discarding: hook %s, tries %+v", st, tries)
	}
	if _, err := database.SetHookStatus(t.Context(), dropped, db.StatusDiscarded, "", ""); err != nil {
		t.Fatal(err)
	}
	if st, tries := status(dropped); st != db.StatusDiscarded || len(tries) != 1 {
		t.Fatalf("after discarding: hook %s, tries %+v", st, tries)
	}
	if err := database.FinishAttempt(t.Context(), mustSchedule(t, database, dropped), db.Outcome{Error: "late"}, time.Second); err != nil {
		t.Fatal(err)
	}
	if st, tries := status(dropped); st != db.StatusDiscarded || len(tries) != 2 {
		t.Fatalf("after a late attempt: hook %s, tries %+v", st, tries)
	}
	c.status = 0

	// Deleting a hook removes its attempts; the worker isn't bothered.
	gone := catch()
	database.DeleteHook(t.Context(), gone)
	run()
}

func TestJSONAutoEscape(t *testing.T) {
	data := newData(testHook(), "https://catchy.test")
	cases := []struct{ name, tmpl, want string }{
		{"quotes and newlines", `{"m": "{{.Payload.message}}"}`, `{"m": "Hi \"there\"\nline 2"}`},
		{"inside if", `{"x": "{{if .Payload.email}}{{.Payload.email}}{{end}}"}`, `{"x": "jane@example.com"}`},
		{"inside range", `[{{range $k, $v := .Payload}}"{{$k}}",{{end}}"end"]`, `["email","message","end"]`},
		{"json passes through", `{"p": {{json .Payload}}}`, `{"p": {"email":"jane@example.com","message":"Hi \"there\"\nline 2"}}`},
		{"variables print nothing", `{{$e := .Payload.email}}{"e": "{{$e}}"}`, `{"e": "jane@example.com"}`},
		{"html isn't escaped", `{"from": "{{.Channel}} <a@b.c>"}`, `{"from": "contact <a@b.c>"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := renderJSON(tc.tmpl, data)
			if err != nil || got != tc.want {
				t.Fatalf("renderJSON = %s, %v\nwant %s", got, err, tc.want)
			}
			if !json.Valid([]byte(got)) {
				t.Fatalf("not JSON: %s", got)
			}
		})
	}

	// Payload paths are safe: anything missing along the way is nothing.
	nested := Data{Channel: "orders", Payload: map[string]any{
		"customer": map[string]any{"email": "jane@example.com", "tags": []any{"vip", "new"}},
	}}
	for _, tc := range []struct{ name, tmpl, want string }{
		{"nested", `{"e": "{{.Payload.customer.email}}"}`, `{"e": "jane@example.com"}`},
		{"array index", `{"t": "{{index .Payload.customer.tags 1}}"}`, `{"t": "new"}`},
		{"missing parent", `{"e": "{{.Payload.order.id}}"}`, `{"e": ""}`},
		{"missing in if", `{"e": "{{if .Payload.order.id}}yes{{else}}no{{end}}"}`, `{"e": "no"}`},
		{"json of nested", `{"c": {{json .Payload.customer.tags}}}`, `{"c": ["vip","new"]}`},
		{"json of missing", `{"c": {{json .Payload.order}}}`, `{"c": null}`},
		{"with", `{"e": "{{with .Payload.customer}}{{.email}}{{end}}"}`, `{"e": "jane@example.com"}`},
		{"root variable", `{"e": "{{range .Payload.customer.tags}}{{$.Payload.customer.email}} {{end}}"}`, `{"e": "jane@example.com jane@example.com "}`},
		{"empty reply_to dropped", `{"reply_to": "{{.Payload.email}}", "s": "x"}`, `{"s": "x"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := renderJSON(tc.tmpl, nested)
			if err != nil || got != tc.want {
				t.Fatalf("renderJSON = %s, %v\nwant %s", got, err, tc.want)
			}
		})
	}
	if got, err := render(`to {{.Payload.order.id}}.`, nested); err != nil || got != "to ." {
		t.Fatalf("plain missing = %q, %v", got, err)
	}

	// Vars come from the channel; missing ones are "".
	withVars := Data{Channel: "sales", Vars: map[string]string{"subject": "New lead", "to": "sales@acme.dev"}}
	if got, err := renderJSON(`{"to": ["{{or .Vars.to "team@acme.dev"}}"], "s": "{{.Vars.subject}}", "x": "{{.Vars.nope}}"}`, withVars); err != nil ||
		got != `{"to": ["sales@acme.dev"], "s": "New lead", "x": ""}` {
		t.Fatalf("vars = %s, %v", got, err)
	}
	if got, err := renderJSON(`{"to": ["{{or .Vars.to "team@acme.dev"}}"]}`, Data{}); err != nil || got != `{"to": ["team@acme.dev"]}` {
		t.Fatalf("no vars = %s, %v", got, err)
	}

	// Plain-text bodies aren't escaped.
	if got, _ := renderBody(`{{.Payload.message}}`, "text/plain", data); got != "Hi \"there\"\nline 2" {
		t.Fatalf("text body = %q", got)
	}
}

func TestDropEmpty(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"to": ["a"], "reply_to": "", "subject": "s"}`, `{"to": ["a"], "subject": "s"}`},
		{`{"reply_to": "x@y.z", "cc": ""}`, `{"reply_to": "x@y.z"}`},
		{`{"subject": ""}`, `{"subject": ""}`}, // only the listed keys
		{`["reply_to", ""]`, `["reply_to", ""]`},
		{`not json`, `not json`},
	}
	for _, tc := range cases {
		if got := dropEmpty(tc.in, "reply_to", "cc", "bcc"); got != tc.want {
			t.Errorf("dropEmpty(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestEnv(t *testing.T) {
	e := env.Env{Vars: map[string]string{"to": "team@acme.dev", "subject": "New hook"}, Secrets: map[string]string{"RESEND": "re_env", "SIG": "sig-env", "HOOK_URL": ""}}

	// Sending: env vars and secrets fill in the URL, headers, body, and
	// signature.
	var got *http.Request
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, body = r, string(b)
	}))
	defer srv.Close()
	e.Secrets["HOOK_URL"] = srv.URL + "/private-token"
	o, err := Validate(HTTP, Options{URL: "{{.Secrets.HOOK_URL}}", SignWith: "SIG", ContentType: "application/json",
		Headers: "Authorization: Bearer {{.Secrets.RESEND}}",
		Body:    `{"to": "{{.Vars.to}}", "subject": "{{.Vars.subject}}"}`}, e)
	if err != nil {
		t.Fatal(err)
	}
	s := &Runner{Env: e}
	dst := db.Handler{Type: HTTP, Options: o.JSON()}
	if _, err := s.Run(t.Context(), dst, testHook()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if body != `{"to": "team@acme.dev", "subject": "New hook"}` || got.Header.Get("Authorization") != "Bearer re_env" || got.URL.Path != "/private-token" {
		t.Fatalf("sent %s to %s with %q", body, got.URL, got.Header.Get("Authorization"))
	}
	mac := hmac.New(sha256.New, []byte("sig-env"))
	mac.Write([]byte(body))
	if got.Header.Get(SignatureHeader) != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("not signed with the secret")
	}

	// Errors name the host only, since the URL can hold a secret.
	e.Secrets["HOOK_URL"] = "http://127.0.0.1:1/private-token"
	if _, err := s.Run(t.Context(), dst, testHook()); err == nil || strings.Contains(err.Error(), "private-token") {
		t.Fatalf("Send to a closed port = %v", err)
	}

	// A secret removed from the environment fails the attempt.
	s.Env = env.Env{}
	if _, err := s.Run(t.Context(), dst, testHook()); err == nil || !strings.Contains(err.Error(), "CATCHY_SECRET_HOOK_URL") {
		t.Fatalf("Send without the secret = %v", err)
	}
}

// mustSchedule queues an attempt for hook on the "fwd" handler, as if it were
// already running, and returns its ID.
func mustSchedule(t *testing.T, database *db.DB, hook string) string {
	t.Helper()
	if _, err := database.EnqueueAttempts(t.Context(), hook, "contact"); err != nil {
		t.Fatal(err)
	}
	attempts, err := database.HookAttempts(t.Context(), []string{hook})
	if err != nil {
		t.Fatal(err)
	}
	return attempts[hook][len(attempts[hook])-1].ID
}
