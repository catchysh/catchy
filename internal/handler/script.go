package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/dop251/goja"

	"github.com/catchysh/catchy/internal/env"
)

// Script limits.
const (
	MaxScriptLen = 64 << 10 // a script's source
	maxOutput    = 4 << 10  // console output kept with an attempt
	maxFetchBody = 1 << 20  // a fetched response's body
)

// ScriptTimeout bounds one run of a script, fetches included.
var ScriptTimeout = 10 * time.Second

// compileScript compiles a script handler's source. It runs inside an async
// function, so it can await and return; the wrapper starts on its first
// line, so error line numbers match the source.
func compileScript(src string) (*goja.Program, error) {
	return goja.Compile("script", "(async () => {"+src+"\n})()", false)
}

// scriptSecretRef finds secrets.NAME in a script, for checking they're set.
var scriptSecretRef = regexp.MustCompile(`\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)`)

// runScript runs a script handler on a hook. It returns what the script
// logged and, when it threw or timed out, the error.
func (s *Runner) runScript(ctx context.Context, src string, data Data, headers map[string]string) (string, error) {
	program, err := compileScript(src)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, ScriptTimeout)
	defer cancel()

	vm := goja.New()
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
	stop := context.AfterFunc(ctx, func() { vm.Interrupt("timed out after " + ScriptTimeout.String()) })
	defer stop()

	var out strings.Builder
	logf := func(level string) func(goja.FunctionCall) goja.Value {
		return func(call goja.FunctionCall) goja.Value {
			var parts []string
			for _, a := range call.Arguments {
				parts = append(parts, consoleText(a))
			}
			line := strings.Join(parts, " ")
			if level != "" {
				line = level + ": " + line
			}
			if out.Len() < maxOutput {
				out.WriteString(line)
				out.WriteByte('\n')
			}
			return goja.Undefined()
		}
	}
	console := vm.NewObject()
	console.Set("log", logf(""))
	console.Set("info", logf(""))
	console.Set("warn", logf("warn"))
	console.Set("error", logf("error"))
	vm.Set("console", console)

	if headers == nil {
		headers = map[string]string{}
	}
	payload := any(data.Payload)
	if data.Payload == nil {
		payload = nil
	}
	vm.Set("hook", map[string]any{
		"id":        data.ID,
		"channel":   data.Channel,
		"payload":   payload,
		"text":      data.Text,
		"body":      data.Body,
		"headers":   headers,
		"url":       data.URL,
		"createdAt": data.CreatedAt.UTC().Format(time.RFC3339),
	})
	vars := data.Vars
	if vars == nil {
		vars = map[string]string{}
	}
	vm.Set("vars", vars)
	vm.Set("secrets", vm.NewDynamicObject(&scriptSecrets{vm: vm, env: data.env}))
	vm.Set("fetch", s.scriptFetch(ctx, vm))

	result, err := vm.RunProgram(program)
	output := strings.TrimRight(out.String(), "\n")
	if err != nil {
		return output, scriptError(err)
	}
	if p, ok := result.Export().(*goja.Promise); ok {
		switch p.State() {
		case goja.PromiseStateRejected:
			return output, scriptError(p.Result())
		case goja.PromiseStatePending:
			return output, errors.New("the script didn't finish")
		}
	}
	return output, nil
}

// scriptError turns what a script threw into an error with just its message.
func scriptError(v any) error {
	switch e := v.(type) {
	case *goja.InterruptedError:
		return fmt.Errorf("script %v", e.Value())
	case *goja.Exception:
		return errors.New(e.Value().String())
	case goja.Value:
		return errors.New(e.String())
	case error:
		return e
	}
	return fmt.Errorf("%v", v)
}

// consoleText prints a value the way console.log would: strings as they are,
// everything else as JSON when it can be.
func consoleText(v goja.Value) string {
	if v == nil || goja.IsUndefined(v) {
		return "undefined"
	}
	if s, ok := v.Export().(string); ok {
		return s
	}
	if b, err := json.Marshal(v.Export()); err == nil {
		return string(b)
	}
	return v.String()
}

// scriptSecrets is the secrets object: secrets.NAME reads CATCHY_SECRET_NAME.
// It lists nothing, so a script can't dump them all, and reading one that
// isn't set throws.
type scriptSecrets struct {
	vm  *goja.Runtime
	env env.Env
}

func (s *scriptSecrets) Get(name string) goja.Value {
	v, err := s.env.Secret(name)
	if err != nil {
		panic(s.vm.NewTypeError(err.Error()))
	}
	return s.vm.ToValue(v)
}
func (s *scriptSecrets) Set(string, goja.Value) bool { return false }
func (s *scriptSecrets) Has(name string) bool        { return s.env.Has(name) }
func (s *scriptSecrets) Delete(string) bool          { return false }
func (s *scriptSecrets) Keys() []string              { return nil }

// scriptFetch is a script's fetch: fetch(url, {method, headers, body})
// makes the request and returns {ok, status, headers, text(), json()}. It's
// synchronous, so await works on it and is optional. Errors name the host
// only, since a URL can hold a secret.
func (s *Runner) scriptFetch(ctx context.Context, vm *goja.Runtime) func(string, map[string]any) *goja.Object {
	return func(target string, init map[string]any) *goja.Object {
		u, err := url.Parse(target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			panic(vm.NewTypeError("fetch needs an http or https URL"))
		}
		method := http.MethodGet
		if m, ok := init["method"].(string); ok && m != "" {
			method = strings.ToUpper(m)
		}
		var body io.Reader
		jsonBody := false
		switch b := init["body"].(type) {
		case nil:
		case string:
			body = strings.NewReader(b)
		default:
			// Anything else is sent as JSON.
			raw, err := json.Marshal(b)
			if err != nil {
				panic(vm.NewTypeError("fetch: the body isn't a string and can't be sent as JSON"))
			}
			body = bytes.NewReader(raw)
			jsonBody = true
		}
		req, err := http.NewRequestWithContext(ctx, method, target, body)
		if err != nil {
			panic(vm.NewTypeError("fetch: " + err.Error()))
		}
		req.Header.Set("User-Agent", "Catchy")
		if h, ok := init["headers"].(map[string]any); ok {
			for k, v := range h {
				req.Header.Set(k, fmt.Sprint(v))
			}
		}
		if jsonBody && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := s.client().Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			panic(vm.NewGoError(fmt.Errorf("fetch %s: %v", u.Host, err)))
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxFetchBody))

		res := vm.NewObject()
		res.Set("ok", resp.StatusCode >= 200 && resp.StatusCode < 300)
		res.Set("status", resp.StatusCode)
		respHeaders := map[string]string{}
		for k := range resp.Header {
			respHeaders[strings.ToLower(k)] = resp.Header.Get(k)
		}
		res.Set("headers", respHeaders)
		res.Set("text", func() string { return string(raw) })
		res.Set("json", func() any {
			var v any
			if err := json.Unmarshal(raw, &v); err != nil {
				panic(vm.NewTypeError(fmt.Sprintf("fetch %s: the response isn't JSON", u.Host)))
			}
			return v
		})
		return res
	}
}
