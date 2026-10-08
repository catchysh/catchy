// Package payload decodes a hook's raw body into fields. Hooks store only the
// body; the payload is derived from it whenever it's needed.
package payload

import (
	"bytes"
	"encoding/json"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
)

// MaxFormMemory caps how much of a multipart body is held in memory while
// decoding; hook bodies are limited to less than this anyway.
const MaxFormMemory = 1 << 20

// Reserved fields are read by channel guards and never part of a payload.
const (
	// HoneypotField is the default hidden form field that real visitors leave
	// empty; honeypot guards can use another.
	HoneypotField = "_gotcha"
	// TurnstileField carries a Cloudflare Turnstile token; the widget adds it
	// to forms automatically.
	TurnstileField = "cf-turnstile-response"
	// ReCAPTCHAField carries a Google reCAPTCHA token; the widget adds it to
	// forms automatically.
	ReCAPTCHAField = "g-recaptcha-response"
)

var reserved = []string{HoneypotField, TurnstileField, ReCAPTCHAField}

// Decode decodes body into fields when it is a JSON object or a form, and
// returns nil for anything else. Form fields become strings, or arrays of
// strings when repeated; multipart file parts are skipped.
//
// Reserved fields are left out. So are empty form fields starting with "_",
// such as a honeypot named "_website" (stored hooks never have a filled one);
// "_" fields with a value, like "_subject", are kept. JSON keys starting with
// "_" are always kept, since webhooks use them for real data (e.g. "_id").
func Decode(contentType string, body []byte) map[string]any {
	fields := Raw(contentType, body)
	for _, f := range reserved {
		delete(fields, f)
	}
	if isForm(contentType) {
		for k := range fields {
			if strings.HasPrefix(k, "_") && !Filled(fields[k]) {
				delete(fields, k)
			}
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// isForm reports whether contentType is an HTML form encoding.
func isForm(contentType string) bool {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	return mediaType == "application/x-www-form-urlencoded" || mediaType == "multipart/form-data"
}

// Raw is Decode with the reserved fields kept.
func Raw(contentType string, body []byte) map[string]any {
	mediaType, params, _ := mime.ParseMediaType(contentType)
	switch {
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		var data map[string]any
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&data); err != nil {
			return nil
		}
		return data
	case mediaType == "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err != nil || len(values) == 0 {
			return nil
		}
		return formFields(values)
	case mediaType == "multipart/form-data":
		form, err := multipart.NewReader(bytes.NewReader(body), params["boundary"]).ReadForm(MaxFormMemory)
		if err != nil {
			return nil
		}
		defer form.RemoveAll()
		if len(form.Value) == 0 {
			return nil
		}
		return formFields(form.Value)
	default:
		return nil
	}
}

func formFields(values url.Values) map[string]any {
	data := make(map[string]any, len(values))
	for k, v := range values {
		if len(v) == 1 {
			data[k] = v[0]
			continue
		}
		// []any rather than []string, matching what JSON decodes to.
		vals := make([]any, len(v))
		for i, s := range v {
			vals[i] = s
		}
		data[k] = vals
	}
	return data
}

// String returns a string field value, or the first value of a repeated one;
// "" for anything else.
func String(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			s, _ := v[0].(string)
			return s
		}
	}
	return ""
}

// Filled reports whether a field value is non-empty: a non-empty string, or
// an array holding one. Any other non-nil value counts as filled.
func Filled(v any) bool {
	switch v := v.(type) {
	case nil:
		return false
	case string:
		return v != ""
	case []any:
		for _, e := range v {
			if Filled(e) {
				return true
			}
		}
		return false
	default:
		return true
	}
}
