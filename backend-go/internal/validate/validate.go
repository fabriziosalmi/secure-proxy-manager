// Package validate enforces the `validate:"..."` struct tags on request models.
//
// The tags existed on 20 fields in internal/models and nothing read them: no
// validator was registered anywhere in the module, so every constraint they
// declared was documentation that the code did not honour (SECURE-DOM-02).
// That mattered most for the length bounds. Handlers hand-check the semantic
// rules — a CIDR parses, a domain has no spaces — but nothing bounded SIZE, so
// a `description` field tagged max=500 accepted anything up to the 55MB global
// body cap and wrote it straight into SQLite.
//
// This implements exactly the tag vocabulary those models use — required,
// omitempty, min, max, oneof — rather than taking a dependency on
// go-playground/validator for five verbs. The dialect is a strict subset of
// that library's, chosen so the existing tags did not have to be rewritten and
// so moving to it later would be a drop-in.
//
// Unknown verbs are an error, not a silent skip: a typo'd rule that quietly
// validates nothing is the failure mode this package exists to fix. Struct()
// reports it as a programming error, and TestTagsAreSupported walks the models
// package so it surfaces at test time rather than at request time.
package validate

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Error is a failed constraint on one field. It carries the JSON field name,
// so the message a client sees names the field it actually sent.
type Error struct {
	Field string
	Rule  string
	Msg   string
}

func (e *Error) Error() string { return e.Field + ": " + e.Msg }

// Struct validates v, which must be a struct or a pointer to one. It returns
// the first violation, so the caller can write a single 400 without leaking a
// field-by-field map of the model's shape.
func Struct(v any) error {
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return fmt.Errorf("validate: nil pointer")
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("validate: want a struct, got %s", rv.Kind())
	}
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("validate")
		if tag == "" || tag == "-" {
			continue
		}
		if err := field(jsonName(f), rv.Field(i), tag); err != nil {
			return err
		}
	}
	return nil
}

// jsonName prefers the json tag so an error names the wire field rather than
// the Go one. The models pad their json tags for alignment, hence TrimSpace.
func jsonName(f reflect.StructField) string {
	name := strings.TrimSpace(strings.SplitN(f.Tag.Get("json"), ",", 2)[0])
	if name == "" || name == "-" {
		return f.Name
	}
	return name
}

func field(name string, v reflect.Value, tag string) error {
	rules := strings.Split(tag, ",")
	// omitempty short-circuits everything after it, so an absent optional field
	// is not then rejected by its own max=. It has to be resolved before the
	// loop because it may appear anywhere in the list.
	for _, rule := range rules {
		if rule == "omitempty" && isEmpty(v) {
			return nil
		}
	}
	for _, rule := range rules {
		verb, arg, _ := strings.Cut(rule, "=")
		switch verb {
		case "", "omitempty":
			// handled above
		case "required":
			if isEmpty(v) {
				return &Error{name, rule, "is required"}
			}
		case "min":
			n, err := bound(arg)
			if err != nil {
				return err
			}
			if size, unit, ok := measure(v); ok && size < n {
				return &Error{name, rule, fmt.Sprintf("must be at least %d %s", n, unit)}
			}
		case "max":
			n, err := bound(arg)
			if err != nil {
				return err
			}
			if size, unit, ok := measure(v); ok && size > n {
				return &Error{name, rule, fmt.Sprintf("must be at most %d %s", n, unit)}
			}
		case "oneof":
			allowed := strings.Fields(arg)
			if !slices.Contains(allowed, v.String()) {
				return &Error{name, rule, "must be one of: " + strings.Join(allowed, ", ")}
			}
		default:
			// Not a client error — the tag itself is wrong.
			return fmt.Errorf("validate: unsupported rule %q on field %q", rule, name)
		}
	}
	return nil
}

func bound(arg string) (int64, error) {
	n, err := strconv.ParseInt(arg, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("validate: bad numeric argument %q", arg)
	}
	return n, nil
}

// measure returns the quantity min/max compare against, and the noun to use in
// the message. Strings are measured in runes, matching go-playground/validator,
// so a bound written for a domain name is not spent early by one multi-byte
// character. ok is false for kinds min/max do not apply to.
func measure(v reflect.Value) (int64, string, bool) {
	switch v.Kind() {
	case reflect.String:
		return int64(utf8.RuneCountInString(v.String())), "characters", true
	case reflect.Slice, reflect.Array, reflect.Map:
		return int64(v.Len()), "items", true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// A numeric bound constrains the value itself, not a length.
		return v.Int(), "in value", true
	default:
		return 0, "", false
	}
}

// isEmpty is the `required` predicate: the field's zero value. For a slice or
// map, nil and empty are both empty — an explicit `[]` should not satisfy a
// required list.
func isEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String, reflect.Slice, reflect.Array, reflect.Map:
		return v.Len() == 0
	case reflect.Pointer, reflect.Interface:
		return v.IsNil()
	default:
		return v.IsZero()
	}
}
