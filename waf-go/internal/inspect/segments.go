package inspect

// The arguments of a request body, for the built-in rules (W.3.2a).
//
// A body matched as one string lets a pattern span two arguments: SQLi-003
// (UPDATE ... SET) matched an "update" in one JSON field and a "set" in
// another, and SSRF-007 read the JSON syntax "qty":22 as a port. A form, a
// JSON document or a multipart body is split into segments "name=value", one
// per argument, and a rule matches when it matches one of them. The name
// stays beside its value, so a rule that reads both (DLP-001 on
// password=...) still does, and a JSON key is a segment of its own when its
// value is an object or an array (PP-001 reads __proto__ as a key).
//
// A body that does not parse, or goes past the limits below, is matched
// whole, as before: breaking the format leaves a request where it was, never
// past the rules.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"sort"
	"strings"
)

const (
	maxSegments  = 100000
	maxJSONDepth = 64
)

var errTooMany = errors.New("too many arguments")

// bodySegments splits body into "name=value" segments by its content type,
// or reports false when it is not a form, JSON or multipart body, or does
// not parse within the limits.
func bodySegments(contentType string, body []byte) ([]string, bool) {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, false
	}
	switch {
	case mt == "application/x-www-form-urlencoded":
		return formSegments(body)
	case mt == "application/json" || strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"):
		return jsonSegments(body)
	case mt == "multipart/form-data":
		return multipartSegments(body, params["boundary"])
	}
	return nil, false
}

// formSegments splits on & as a form is read: an encoded %26 inside a value
// stays in it (the normalizer decodes it later, segment by segment).
func formSegments(body []byte) ([]string, bool) {
	parts := strings.Split(string(body), "&")
	if len(parts) > maxSegments {
		return nil, false
	}
	segs := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			segs = append(segs, p)
		}
	}
	return segs, len(segs) > 0
}

// jsonSegments walks a JSON document: each scalar becomes "key=value" with
// the key of the object it is in ("" at the top or in a top-level array),
// and each key whose value is an object or an array "key=". One document
// only; anything after it is not JSON.
func jsonSegments(body []byte) ([]string, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var segs []string
	type frame struct {
		object  bool
		wantKey bool
		key     string
	}
	var stack []frame
	emit := func(key, value string) error {
		if len(segs) >= maxSegments {
			return errTooMany
		}
		segs = append(segs, key+"="+value)
		return nil
	}
	// keyHere is the key the next value belongs to.
	keyHere := func() string {
		if n := len(stack); n > 0 {
			return stack[n-1].key
		}
		return ""
	}
	// valueDone moves an object back to expecting a key.
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].wantKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		top := len(stack) - 1
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if len(stack) >= maxJSONDepth {
					return nil, false
				}
				key := keyHere()
				if top >= 0 && stack[top].object {
					if err := emit(key, ""); err != nil {
						return nil, false
					}
				}
				stack = append(stack, frame{object: t == '{', wantKey: t == '{', key: key})
			case '}', ']':
				stack = stack[:top]
				valueDone()
			}
		case string:
			if top >= 0 && stack[top].object && stack[top].wantKey {
				stack[top].key, stack[top].wantKey = t, false
				continue
			}
			if err := emit(keyHere(), t); err != nil {
				return nil, false
			}
			valueDone()
		default: // json.Number, bool, nil
			v := "null"
			switch t := t.(type) {
			case json.Number:
				v = t.String()
			case bool:
				v = "false"
				if t {
					v = "true"
				}
			}
			if err := emit(keyHere(), v); err != nil {
				return nil, false
			}
			valueDone()
		}
		if len(stack) == 0 && dec.More() {
			return nil, false // a second document
		}
	}
	return segs, len(segs) > 0
}

// multipartSegments makes each part two segments: its headers as sent
// (Content-Disposition with the file name, Content-Type), which the rules
// read for an upload's name and type, and "name=content", a file's content
// included, as the rules read it in the whole body.
func multipartSegments(body []byte, boundary string) ([]string, bool) {
	if boundary == "" {
		return nil, false
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var segs []string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil || len(segs)+2 > maxSegments {
			return nil, false
		}
		content, err := io.ReadAll(part)
		if err != nil {
			return nil, false
		}
		var hdr strings.Builder
		keys := make([]string, 0, len(part.Header))
		for k := range part.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys) // a header map has no order; the segment must
		for _, k := range keys {
			for _, v := range part.Header[k] {
				hdr.WriteString(k + ": " + v + "\n")
			}
		}
		segs = append(segs, hdr.String(), part.FormName()+"="+string(content))
	}
	return segs, len(segs) > 0
}
