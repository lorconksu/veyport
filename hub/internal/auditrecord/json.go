package auditrecord

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// Decode rejects duplicates at every nesting level, unknown and case-aliased
// fields, trailing values, excessive depth, invalid UTF-8 and oversized input.
func Decode(data []byte, dst any, max int) error {
	if len(data) == 0 || len(data) > max || !utf8.Valid(data) {
		return ErrSchema
	}
	t := reflect.TypeOf(dst)
	if t == nil || t.Kind() != reflect.Pointer {
		return ErrSchema
	}
	if t.Elem().Kind() == reflect.Struct && !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return ErrSchema
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if scan(d, t.Elem(), 0) != nil {
		return ErrSchema
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrSchema
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return ErrSchema
	}
	return nil
}

func scan(d *json.Decoder, t reflect.Type, depth int) error {
	if depth > 32 {
		return ErrSchema
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, err := d.Token()
	if err != nil {
		return ErrSchema
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		if t.Kind() != reflect.Struct || t == reflect.TypeFor[time.Time]() {
			return ErrSchema
		}
		fields := map[string]reflect.Type{}
		collectFields(t, fields)
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return ErrSchema
			}
			s, ok := k.(string)
			ft, known := fields[s]
			if !ok || !known || seen[s] {
				return ErrSchema
			}
			seen[s] = true
			if scan(d, ft, depth+1) != nil {
				return ErrSchema
			}
		}
	case '[':
		if t.Kind() != reflect.Slice && t.Kind() != reflect.Array {
			return ErrSchema
		}
		for d.More() {
			if scan(d, t.Elem(), depth+1) != nil {
				return ErrSchema
			}
		}
	default:
		return ErrSchema
	}
	_, err = d.Token()
	return err
}

func collectFields(t reflect.Type, out map[string]reflect.Type) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "-" {
			continue
		}
		if f.Anonymous && tag == "" {
			collectFields(f.Type, out)
			continue
		}
		if tag == "" {
			tag = f.Name
		}
		out[tag] = f.Type
	}
}
