package payload

import (
	"encoding/json"
	"fmt"
	"mime/multipart"
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	var mp strings.Builder
	mw := multipart.NewWriter(&mp)
	mw.WriteField("name", "Jane")
	fw, _ := mw.CreateFormFile("file", "a.txt")
	fw.Write([]byte("skipped"))
	mw.Close()

	cases := []struct {
		name        string
		contentType string
		body        string
		want        string // fmt of the fields; "<nil>" for none
	}{
		{"JSON object", "application/json", `{"a":"b","n":1.50}`, "map[a:b n:1.50]"},
		{"JSON with charset", "application/json; charset=utf-8", `{"a":"b"}`, "map[a:b]"},
		{"+json suffix", "application/vnd.api+json", `{"a":"b"}`, "map[a:b]"},
		{"JSON array", "application/json", `["a"]`, "<nil>"},
		{"invalid JSON", "application/json", `{"a":`, "<nil>"},
		{"form", "application/x-www-form-urlencoded", "a=b&t=x&t=y", "map[a:b t:[x y]]"},
		{"multipart skips files", mw.FormDataContentType(), mp.String(), "map[name:Jane]"},
		{"XML", "application/xml", "<a/>", "<nil>"},
		{"no content type", "", `{"a":"b"}`, "<nil>"},
		{"reserved fields are left out", "application/x-www-form-urlencoded", "a=b&_gotcha=x&cf-turnstile-response=tok&g-recaptcha-response=tok", "map[a:b]"},
		{"only reserved fields", "application/json", `{"_gotcha":""}`, "<nil>"},
		{"empty form fields starting with _ are left out", "application/x-www-form-urlencoded", "email=a&_website=&_ts=123&_subject=Hello", "map[_subject:Hello _ts:123 email:a]"},
		{"JSON keys starting with _ are kept", "application/json", `{"_id":"1","_links":{"self":"x"},"_gotcha":""}`, "map[_id:1 _links:map[self:x]]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := "<nil>"
			if fields := Decode(tc.contentType, []byte(tc.body)); fields != nil {
				got = fmt.Sprint(fields)
			}
			if got != tc.want {
				t.Fatalf("Decode = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRawKeepsReservedFields(t *testing.T) {
	fields := Raw("application/x-www-form-urlencoded", []byte("a=b&_gotcha=x&cf-turnstile-response=tok"))
	if fields[HoneypotField] != "x" || String(fields[TurnstileField]) != "tok" {
		t.Fatalf("Raw = %v", fields)
	}
}

func TestFilled(t *testing.T) {
	for _, tc := range []struct {
		v    any
		want bool
	}{
		{nil, false}, {"", false}, {"x", true}, {[]any{"", ""}, false}, {[]any{"", "x"}, true}, {json.Number("0"), true},
	} {
		if got := Filled(tc.v); got != tc.want {
			t.Errorf("Filled(%#v) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

func TestDecodeKeepsJSONNumbers(t *testing.T) {
	fields := Decode("application/json", []byte(`{"n":12345678901234567890}`))
	if fields["n"] != json.Number("12345678901234567890") {
		t.Fatalf("n = %#v, want the exact number", fields["n"])
	}
}
