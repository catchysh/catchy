// Package handler runs a channel's handlers on each hook it catches. A
// handler has a type; today that's http, a request built from templates,
// which covers webhooks, chat (Slack, Discord), and email APIs (Resend).
// This package checks handlers, runs them, and runs the worker that works
// through queued attempts, retrying failed ones.
package handler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"text/template/parse"
	"time"

	"github.com/catchysh/catchy/internal/db"
	"github.com/catchysh/catchy/internal/env"
	"github.com/catchysh/catchy/internal/payload"
)

// Handler types.
const (
	HTTP = "http" // an HTTP request to a URL
)

// Types lists every handler type, in display order.
var Types = []string{HTTP}

// SignatureHeader carries the signature of signed requests: "sha256=" and
// the hex HMAC-SHA256 of the body, the format hmac guards check.
const SignatureHeader = "X-Catchy-Signature"

// Options are a handler's settings. URL, Headers, and Body are
// text/template templates; see Data for what they can use. Secrets are used
// by name, like {{.Secrets.SLACK_WEBHOOK_URL}}, so none are stored here.
type Options struct {
	Method      string `json:"method,omitempty"`
	URL         string `json:"url,omitempty"`
	Headers     string `json:"headers,omitempty"`      // "Name: value" lines
	ContentType string `json:"content_type,omitempty"` // for a templated Body
	// Body is the request body. Empty forwards the hook as received, with its
	// content type.
	Body string `json:"body,omitempty"`
	// SignWith names the secret that signs each request's body, if any.
	SignWith string `json:"sign_with,omitempty"`
}

// ParseOptions decodes options stored as JSON.
func ParseOptions(raw string) (Options, error) {
	var o Options
	if raw == "" {
		return o, nil
	}
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		return o, fmt.Errorf("decoding handler options: %w", err)
	}
	return o, nil
}

// JSON encodes options for storage.
func (o Options) JSON() string {
	b, _ := json.Marshal(o)
	return string(b)
}

// Preset is a ready-made handler configuration the dashboard offers.
type Preset struct {
	Name        string
	Label       string
	Description string
	Group       string
	Type        string
	URLHint     string // placeholder when the preset leaves the URL to the user
	Options     Options
}

const (
	resendBody = `{
  "from": "Catchy <hooks@example.com>",
  "to": ["team@example.com"],
  "reply_to": "{{.Payload.email}}",
  "subject": "New hook in #{{.Channel}}",
  "text": "{{.Text}}\n\n{{.URL}}"
}`
	slackBody   = `{"text": "New hook in #{{.Channel}}\n\n{{.Text}}"}`
	discordBody = `{"content": "New hook in #{{.Channel}}\n\n{{.Text}}"}`
)

// Presets are the dashboard's handler choices, grouped, in display order.
var Presets = []Preset{
	{"resend", "Resend", "Email each hook through Resend's API, with the RESEND_API_KEY secret; edit from and to in the body.", "Email", HTTP, "",
		Options{Method: http.MethodPost, URL: "https://api.resend.com/emails", Headers: "Authorization: Bearer {{.Secrets.RESEND_API_KEY}}", ContentType: "application/json", Body: resendBody}},
	{"slack", "Slack", "Post each hook to the Slack incoming webhook in the SLACK_WEBHOOK_URL secret.", "Chat", HTTP, "",
		Options{Method: http.MethodPost, URL: "{{.Secrets.SLACK_WEBHOOK_URL}}", ContentType: "application/json", Body: slackBody}},
	{"discord", "Discord", "Post each hook to the Discord webhook in the DISCORD_WEBHOOK_URL secret.", "Chat", HTTP, "",
		Options{Method: http.MethodPost, URL: "{{.Secrets.DISCORD_WEBHOOK_URL}}", ContentType: "application/json", Body: discordBody}},
	{"forward", "Webhook URL", "Forward each hook as received to your URL.", "Forward", HTTP, "https://example.com/hooks",
		Options{Method: http.MethodPost}},
	{"signed", "Signed webhook", "Forward each hook to your URL, signed with the WEBHOOK_SIGNING_SECRET secret in X-Catchy-Signature.", "Forward", HTTP, "https://example.com/hooks",
		Options{Method: http.MethodPost, SignWith: "WEBHOOK_SIGNING_SECRET"}},
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

// Validate checks a handler's settings and returns them with defaults
// filled in. Templates are rendered with a sample hook, so mistakes show up
// now rather than on the first hook: a JSON body must come out as valid JSON,
// the URL as an http or https URL. Secrets that aren't set in e are allowed;
// attempts fail until they are.
func Validate(typ string, opts Options, e env.Env) (Options, error) {
	if typ != HTTP {
		return Options{}, fmt.Errorf("unknown handler type %q: use %s", typ, strings.Join(Types, ", "))
	}
	if opts.Method == "" {
		opts.Method = http.MethodPost
	}
	if !slices.Contains([]string{http.MethodPost, http.MethodPut, http.MethodPatch}, opts.Method) {
		return Options{}, fmt.Errorf("unsupported method %q: use POST, PUT, or PATCH", opts.Method)
	}
	out := Options{Method: opts.Method, URL: strings.TrimSpace(opts.URL), Headers: strings.TrimSpace(opts.Headers), Body: opts.Body, SignWith: strings.TrimSpace(opts.SignWith)}
	// Secrets that aren't set yet are allowed: they're flagged in the
	// dashboard, and attempts fail until they're set. The sample fills them
	// in with a URL, so a URL that's one secret still checks out.
	sample := sampleData()
	sample.Vars = e.Vars
	sample.env = env.Env{Vars: e.Vars, Secrets: map[string]string{}}
	for name, v := range e.Secrets {
		sample.env.Secrets[name] = v
	}
	for _, name := range SecretsUsed(out) {
		if !env.ValidName(name) {
			return Options{}, fmt.Errorf("secret names are letters, digits, and _; %q isn't one", name)
		}
		if !e.Has(name) {
			sample.env.Secrets[name] = "https://example.com/" + name
		}
	}
	if out.URL == "" {
		return Options{}, errors.New("a handler needs a URL")
	}
	raw, err := render(out.URL, sample)
	if err != nil {
		return Options{}, fmt.Errorf("URL: %w", err)
	}
	if u, err := url.Parse(raw); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Options{}, errors.New("the URL must be an http or https URL once filled in")
	}
	if u, err := render(out.URL, tainted(sample)); err == nil && strings.Contains(u, taintMarker) {
		return Options{}, errors.New("the URL can't come from the hook, or anyone could make Catchy send requests anywhere")
	}
	for _, line := range headerLines(out.Headers) {
		name, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return Options{}, fmt.Errorf("headers are \"Name: value\" lines; %q isn't one", line)
		}
		if _, err := render(value, sample); err != nil {
			return Options{}, fmt.Errorf("header %s: %w", strings.TrimSpace(name), err)
		}
	}
	if out.Body != "" {
		out.ContentType = strings.TrimSpace(opts.ContentType)
		if out.ContentType == "" {
			out.ContentType = "application/json"
		}
		body, err := renderBody(out.Body, out.ContentType, sample)
		if err != nil {
			return Options{}, fmt.Errorf("body: %w", err)
		}
		if strings.Contains(out.ContentType, "json") && !json.Valid([]byte(body)) {
			return Options{}, errors.New("the body isn't valid JSON when filled in with a sample hook; check quotes and commas, and use {{json …}} for values")
		}
		if strings.Contains(out.ContentType, "json") {
			if err := checkRecipients(out.Body, out.ContentType, sample); err != nil {
				return Options{}, err
			}
		}
	}
	return out, nil
}

// SecretsUsed returns the names of the secrets a handler's settings use.
func SecretsUsed(o Options) []string {
	var names []string
	for _, m := range secretRef.FindAllStringSubmatch(o.URL+"\n"+o.Headers+"\n"+o.Body, -1) {
		names = append(names, m[1])
	}
	if o.SignWith != "" {
		names = append(names, o.SignWith)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

var secretRef = regexp.MustCompile(`\.Secrets\.([A-Za-z_][A-Za-z0-9_]*)`)

// Describe summarizes a handler for display, e.g. "http · POST
// api.resend.com", "http · POST {{.Secrets.SLACK_WEBHOOK_URL}}", or
// "http · POST example.com · forward · signed".
func Describe(typ string, o Options) string {
	where := o.URL
	if u, err := url.Parse(o.URL); err == nil && u.Host != "" && !strings.Contains(o.URL, "{{") {
		where = u.Host
	}
	s := typ + " · " + o.Method + " " + where
	if o.Body == "" {
		s += " · forward"
	}
	if o.SignWith != "" {
		s += " · signed"
	}
	return s
}

// headerLines splits a headers template into its non-empty lines.
func headerLines(headers string) []string {
	var out []string
	for _, line := range strings.Split(headers, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// Recipients are the email fields a hook mustn't fill in: otherwise anyone
// could send email anywhere through the handler.
var Recipients = []string{"from", "to", "cc", "bcc"}

// taintMarker stands in for everything from the hook in tainted data.
const taintMarker = "catchy-hook-value"

// tainted returns d with everything that comes from the hook replaced by
// taintMarker, to check where hook values end up.
func tainted(d Data) Data {
	d.taint = taintMarker
	d.Payload = map[string]any{taintMarker: taintMarker}
	d.Text, d.Body = taintMarker, taintMarker
	return d
}

// checkRecipients renders a JSON body with tainted data and fails if hook
// values reach a recipient field.
func checkRecipients(body, contentType string, sample Data) error {
	marker := taintMarker
	out, err := renderBody(body, contentType, tainted(sample))
	if err != nil {
		return nil // the real render already passed; nothing more to learn
	}
	var fields map[string]any
	if json.Unmarshal([]byte(out), &fields) != nil {
		return nil
	}
	for _, k := range Recipients {
		if v, ok := fields[k]; ok && strings.Contains(text(v), marker) {
			return fmt.Errorf("%q can't come from the hook, or anyone could send email anywhere; use fixed addresses or {{.Vars.…}}", k)
		}
	}
	return nil
}

// sampleData is a made-up contact-form hook, for checking templates.
func sampleData() Data {
	d := newData(db.Hook{
		ID: "01sample", Channel: "contact", CreatedAt: time.Now(),
		ContentType: "application/x-www-form-urlencoded",
		Body:        []byte(`name=Jane+Doe&email=jane%40example.com&message=Hello+%22there%22`),
	}, "https://catchy.example.com")
	return d
}

// Templates

// Data is what Subject, Body, and ReplyTo templates can use.
type Data struct {
	ID        string
	Channel   string
	CreatedAt time.Time
	Payload   map[string]any    // the decoded body, e.g. {{.Payload.email}}; nil when it isn't JSON or a form
	Text      string            // Payload as "key: value" lines, sorted
	Body      string            // the raw body
	URL       string            // the hook in the dashboard
	Vars      map[string]string // CATCHY_VAR_ variables, e.g. {{.Vars.subject}}; missing ones are ""

	// taint, when set, stands in for everything that comes from the hook,
	// to check where hook values end up.
	taint string
	// env has the CATCHY_SECRET_ variables, for {{.Secrets.NAME}}.
	env env.Env
}

var funcs = template.FuncMap{
	// json encodes a value as JSON, e.g. {{json .Payload}} for the whole
	// payload as an object.
	"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	},
	// text prints a value as text: strings as they are, objects and arrays as
	// JSON, nothing for a missing value. Printed values go through it
	// automatically.
	"text": text,
	// payloadPath looks up a path in the payload; .Payload.a.b in a template
	// becomes payloadPath "a.b". It's bound to the hook when executing.
	"payloadPath": func(string) any { return nil },
	// secretValue returns a secret; .Secrets.NAME in a template becomes
	// secretValue "NAME". It's bound when executing.
	"secretValue": func(string) (string, error) { return "", nil },
	// jsonString escapes a value's text for inside a JSON string; JSON bodies
	// apply it to every printed value automatically.
	"jsonString": func(v any) string {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		enc.Encode(text(v))
		s := strings.TrimSpace(b.String())
		return s[1 : len(s)-1]
	},
}

// escapeActions appends the printer function (jsonString or text) to every
// printing action in a template, except those already ending in json.
func escapeActions(tree *parse.Tree, node parse.Node, printer string) {
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, c := range n.Nodes {
			escapeActions(tree, c, printer)
		}
	case *parse.ActionNode:
		cmds := n.Pipe.Cmds
		if len(n.Pipe.Decl) > 0 || len(cmds) == 0 {
			return // a variable declaration prints nothing
		}
		if id, ok := cmds[len(cmds)-1].Args[0].(*parse.IdentifierNode); ok && id.Ident == "json" {
			return
		}
		ident := parse.NewIdentifier(printer).SetTree(tree).SetPos(n.Pos)
		n.Pipe.Cmds = append(cmds, &parse.CommandNode{NodeType: parse.NodeCommand, Pos: n.Pos, Args: []parse.Node{ident}})
	case *parse.IfNode:
		escapeActions(tree, n.List, printer)
		escapeActions(tree, n.ElseList, printer)
	case *parse.RangeNode:
		escapeActions(tree, n.List, printer)
		escapeActions(tree, n.ElseList, printer)
	case *parse.WithNode:
		escapeActions(tree, n.List, printer)
		escapeActions(tree, n.ElseList, printer)
	}
}

// rewritePayloadPaths turns every .Payload.a.b (or $.Payload.a.b) in a
// template into (payloadPath "a.b"), so a missing key anywhere along the
// path gives nothing instead of failing the template, and every
// .Secrets.NAME into (secretValue "NAME"), which fails when it isn't set.
func rewritePayloadPaths(node parse.Node) error {
	var err error
	var walkPipe func(p *parse.PipeNode)
	var walk func(n parse.Node)
	walkPipe = func(p *parse.PipeNode) {
		if p == nil {
			return
		}
		for _, cmd := range p.Cmds {
			for i, arg := range cmd.Args {
				var ident []string
				switch a := arg.(type) {
				case *parse.FieldNode:
					ident = a.Ident
				case *parse.VariableNode:
					if len(a.Ident) > 1 && a.Ident[0] == "$" {
						ident = a.Ident[1:]
					}
				case *parse.PipeNode:
					walkPipe(a)
				}
				var fn, path string
				switch {
				case len(ident) > 1 && ident[0] == "Payload":
					fn, path = "payloadPath", strings.Join(ident[1:], ".")
				case len(ident) > 0 && ident[0] == "Secrets":
					if len(ident) != 2 {
						err = errors.New("use a secret by its name: {{.Secrets.NAME}}")
						return
					}
					fn, path = "secretValue", ident[1]
				default:
					continue
				}
				lookupNode, e := callNode(fn, path)
				if e != nil {
					err = e
					return
				}
				cmd.Args[i] = lookupNode
			}
		}
	}
	walk = func(n parse.Node) {
		switch n := n.(type) {
		case *parse.ListNode:
			if n == nil {
				return
			}
			for _, c := range n.Nodes {
				walk(c)
			}
		case *parse.ActionNode:
			walkPipe(n.Pipe)
		case *parse.IfNode:
			walkPipe(n.Pipe)
			walk(n.List)
			walk(n.ElseList)
		case *parse.RangeNode:
			walkPipe(n.Pipe)
			walk(n.List)
			walk(n.ElseList)
		case *parse.WithNode:
			walkPipe(n.Pipe)
			walk(n.List)
			walk(n.ElseList)
		case *parse.TemplateNode:
			walkPipe(n.Pipe)
		}
	}
	walk(node)
	return err
}

// callNode builds a (fn "arg") node by parsing it, so it comes out exactly as
// the template package would build it.
func callNode(fn, arg string) (parse.Node, error) {
	t, err := template.New("").Funcs(funcs).Parse("{{(" + fn + " " + strconv.Quote(arg) + ")}}")
	if err != nil {
		return nil, err
	}
	return t.Tree.Root.Nodes[0].(*parse.ActionNode).Pipe.Cmds[0].Args[0], nil
}

// lookup follows a dotted path through nested objects, returning nil when
// any part is missing.
func lookup(v any, path string) any {
	for _, part := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[part]
	}
	return v
}

// dropEmpty removes the given top-level keys from a JSON object when their
// value is an empty string, keeping the other keys in order. Anything that
// isn't such an object is returned unchanged.
func dropEmpty(body string, keys ...string) string {
	dec := json.NewDecoder(strings.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return body
	}
	type kv struct {
		key string
		val json.RawMessage
	}
	var fields []kv
	dropped := false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return body
		}
		key, _ := tok.(string)
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return body
		}
		if slices.Contains(keys, key) && string(val) == `""` {
			dropped = true
			continue
		}
		fields = append(fields, kv{key, val})
	}
	if !dropped {
		return body
	}
	var b strings.Builder
	b.WriteString("{")
	for i, f := range fields {
		if i > 0 {
			b.WriteString(", ")
		}
		k, _ := json.Marshal(f.key)
		b.Write(k)
		b.WriteString(": ")
		b.Write(f.val)
	}
	b.WriteString("}")
	return b.String()
}

func parseTemplate(text string) (*template.Template, error) {
	t, err := template.New("").Funcs(funcs).Option("missingkey=zero").Parse(text)
	if err != nil {
		return nil, fmt.Errorf("template error: %w", err)
	}
	return t, nil
}

func render(text string, data Data) (string, error) {
	return execute(text, data, false)
}

// renderBody renders a body template, escaping values for JSON when the
// content type is JSON.
func renderBody(text, contentType string, data Data) (string, error) {
	if strings.Contains(contentType, "json") {
		return renderJSON(text, data)
	}
	return render(text, data)
}

// renderJSON renders a JSON body template. Every value it prints is escaped
// for a JSON string, so `"subject": "New hook in #{{.Channel}}"` stays valid
// whatever the channel or fields contain; {{json …}} output, already JSON, is
// left as is. Empty "reply_to", "cc", and "bcc" are then dropped, so email
// APIs don't reject a blank address when a hook has no email field.
func renderJSON(text string, data Data) (string, error) {
	out, err := execute(text, data, true)
	if err != nil || out == "" {
		return out, err
	}
	return dropEmpty(out, "reply_to", "cc", "bcc"), nil
}

func execute(text string, data Data, jsonEscape bool) (string, error) {
	if text == "" {
		return "", nil
	}
	t, err := parseTemplate(text)
	if err != nil {
		return "", err
	}
	if err := rewritePayloadPaths(t.Tree.Root); err != nil {
		return "", err
	}
	// Printed values go through jsonString in JSON bodies, and through text
	// otherwise, so a missing value prints as nothing rather than "<no value>".
	printer := "text"
	if jsonEscape {
		printer = "jsonString"
	}
	escapeActions(t.Tree, t.Tree.Root, printer)
	t.Funcs(template.FuncMap{"payloadPath": func(path string) any {
		if data.taint != "" {
			return data.taint
		}
		return lookup(data.Payload, path)
	}, "secretValue": data.env.Secret})
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return "", fmt.Errorf("template error: %w", err)
	}
	return b.String(), nil
}

func newData(h db.Hook, dashboard string) Data {
	d := Data{ID: h.ID, Channel: h.Channel, CreatedAt: h.CreatedAt, Body: string(h.Body),
		URL: dashboard + "/" + h.ID}
	d.Payload = payload.Decode(h.ContentType, h.Body)
	keys := make([]string, 0, len(d.Payload))
	for k := range d.Payload {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var lines []string
	for _, k := range keys {
		lines = append(lines, k+": "+text(d.Payload[k]))
	}
	d.Text = strings.Join(lines, "\n")
	if d.Text == "" {
		d.Text = d.Body
	}
	return d
}

func text(v any) string {
	switch v := v.(type) {
	case nil:
		return ""
	case string:
		return v
	case []any:
		parts := make([]string, len(v))
		for i, p := range v {
			parts[i] = text(p)
		}
		return strings.Join(parts, ", ")
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// Sending

// Runner runs handlers on hooks.
type Runner struct {
	// Dashboard is the dashboard's base URL, for links in messages.
	Dashboard string
	// Client makes the requests; nil uses a client with a timeout.
	Client *http.Client
	// Env has the variables and secrets from the environment.
	Env env.Env
}

func (s *Runner) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Run runs a handler on a hook and returns the HTTP status of the
// response, if there was one. A returned error means it should be retried.
func (s *Runner) Run(ctx context.Context, dst db.Handler, h db.Hook) (int, error) {
	if dst.Type != HTTP {
		return 0, fmt.Errorf("unknown handler type %q", dst.Type)
	}
	o, err := ParseOptions(dst.Options)
	if err != nil {
		return 0, err
	}
	for _, name := range SecretsUsed(o) {
		if _, err := s.Env.Secret(name); err != nil {
			return 0, err
		}
	}
	data := newData(h, strings.TrimRight(s.Dashboard, "/"))
	data.Vars = s.Env.Vars
	data.env = s.Env

	target, err := render(o.URL, data)
	if err != nil {
		return 0, fmt.Errorf("URL: %w", err)
	}
	body, contentType := h.Body, h.ContentType
	if o.Body != "" {
		rendered, err := renderBody(o.Body, o.ContentType, data)
		if err != nil {
			return 0, err
		}
		body, contentType = []byte(rendered), o.ContentType
	}
	// Errors mention the host only: the URL itself may hold a secret.
	req, err := http.NewRequestWithContext(ctx, o.Method, target, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("the URL isn't valid once filled in")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", "Catchy")
	req.Header.Set("X-Catchy-Hook-Id", h.ID)
	req.Header.Set("X-Catchy-Channel", h.Channel)
	for _, line := range headerLines(o.Headers) {
		name, value, _ := strings.Cut(line, ":")
		v, err := render(strings.TrimSpace(value), data)
		if err != nil {
			return 0, err
		}
		req.Header.Set(strings.TrimSpace(name), v)
	}
	if o.SignWith != "" {
		secret, err := s.Env.Secret(o.SignWith)
		if err != nil {
			return 0, fmt.Errorf("signing: %w", err)
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set(SignatureHeader, "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	return s.do(req)
}

// do sends a request; anything but a 2xx response is an error, with the
// start of the response body.
func (s *Runner) do(req *http.Request) (int, error) {
	resp, err := s.client().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return 0, fmt.Errorf("%s %s: %v", ue.Op, req.URL.Host, ue.Err)
		}
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, nil
	}
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	msg := strings.TrimSpace(string(snippet))
	if msg == "" {
		return resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
}

// Worker

// Backoff is the wait before each retry; after the last one an attempt gives
// up.
var Backoff = []time.Duration{10 * time.Second, 40 * time.Second, 90 * time.Second, 160 * time.Second}

// Worker sends due attempts.
type Worker struct {
	DB     *db.DB
	Runner *Runner
	// Interval is how often it checks for due attempts; zero means a second.
	Interval time.Duration
}

// Run sends due attempts until ctx is done.
func (w *Worker) Run(ctx context.Context) {
	interval := w.Interval
	if interval == 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := w.RunOnce(ctx); err != nil && ctx.Err() == nil {
			log.Printf("attempts: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce sends the attempts that are due now.
func (w *Worker) RunOnce(ctx context.Context) error {
	due, err := w.DB.ClaimDueAttempts(ctx, 20, 2*time.Minute)
	if err != nil {
		return err
	}
	for _, dl := range due {
		var retryIn time.Duration
		start := time.Now()
		status, err := w.Runner.Run(ctx, dl.Handler, dl.Hook)
		outcome := db.Outcome{HTTPStatus: status, MS: time.Since(start).Milliseconds()}
		if err != nil {
			outcome.Error = err.Error()
			// Attempt n is retried after Backoff[n-1], while there is one.
			if dl.Number <= len(Backoff) {
				retryIn = Backoff[dl.Number-1]
			}
		}
		if err := w.DB.FinishAttempt(ctx, dl.ID, outcome, retryIn); err != nil {
			return err
		}
	}
	return nil
}
