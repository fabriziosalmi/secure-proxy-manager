package validate

import (
	"reflect"
	"strings"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
)

type sample struct {
	Name     string   `json:"name"      validate:"required,min=2,max=5"`
	Note     string   `json:"note"      validate:"omitempty,max=4"`
	Kind     string   `json:"kind"      validate:"required,oneof=ip domain"`
	Tags     []string `json:"tags"      validate:"required,min=1,max=3"`
	Untagged string   `json:"untagged"`
	hidden   string   //nolint:unused // exercises the unexported-field skip
}

func valid() sample {
	return sample{Name: "abc", Kind: "ip", Tags: []string{"a"}}
}

func TestStruct(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*sample)
		field   string // "" means the input must be accepted
		wantMsg string
	}{
		{"valid", func(*sample) {}, "", ""},
		{"required string empty", func(s *sample) { s.Name = "" }, "name", "is required"},
		{"below min", func(s *sample) { s.Name = "a" }, "name", "at least 2"},
		{"at min", func(s *sample) { s.Name = "ab" }, "", ""},
		{"at max", func(s *sample) { s.Name = "abcde" }, "", ""},
		{"above max", func(s *sample) { s.Name = "abcdef" }, "name", "at most 5"},
		{"omitempty skips max when absent", func(s *sample) { s.Note = "" }, "", ""},
		{"omitempty still bounds a present value", func(s *sample) { s.Note = "toolong" }, "note", "at most 4"},
		{"oneof rejects", func(s *sample) { s.Kind = "url" }, "kind", "must be one of: ip, domain"},
		{"oneof accepts the second option", func(s *sample) { s.Kind = "domain" }, "", ""},
		{"required slice nil", func(s *sample) { s.Tags = nil }, "tags", "is required"},
		{"required slice empty is not satisfied", func(s *sample) { s.Tags = []string{} }, "tags", "is required"},
		{"slice above max", func(s *sample) { s.Tags = []string{"a", "b", "c", "d"} }, "tags", "at most 3 items"},
		{"untagged field is ignored", func(s *sample) { s.Untagged = strings.Repeat("x", 10_000) }, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := valid()
			tc.mutate(&s)
			err := Struct(&s)
			if tc.field == "" {
				if err != nil {
					t.Fatalf("expected accepted, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected a violation on %q, got nil", tc.field)
			}
			var ve *Error
			if !asValidationError(err, &ve) {
				t.Fatalf("expected a *validate.Error, got %T: %v", err, err)
			}
			if ve.Field != tc.field {
				t.Errorf("field = %q, want %q", ve.Field, tc.field)
			}
			if !strings.Contains(ve.Msg, tc.wantMsg) {
				t.Errorf("msg = %q, want it to contain %q", ve.Msg, tc.wantMsg)
			}
		})
	}
}

func asValidationError(err error, out **Error) bool {
	ve, ok := err.(*Error)
	if ok {
		*out = ve
	}
	return ok
}

// A max on a string is a bound on characters, not bytes: a rule written for a
// 253-character domain must not be spent by three-byte runes.
func TestStringBoundsCountRunes(t *testing.T) {
	s := valid()
	s.Name = "日本語" // 3 runes, 9 bytes — inside max=5, outside it if measured in bytes
	if err := Struct(&s); err != nil {
		t.Fatalf("a 3-rune value was rejected against max=5: %v", err)
	}
}

func TestStructRejectsNonStructInput(t *testing.T) {
	if err := Struct(42); err == nil {
		t.Error("expected an error for a non-struct")
	}
	var p *sample
	if err := Struct(p); err == nil {
		t.Error("expected an error for a nil pointer")
	}
}

// A misspelled rule must be loud. The whole point of this package is that a
// constraint nobody enforces is worse than no constraint, and a typo that
// silently validates nothing recreates exactly that.
func TestUnknownRuleIsAnError(t *testing.T) {
	type bad struct {
		X string `json:"x" validate:"requird"`
	}
	err := Struct(&bad{})
	if err == nil {
		t.Fatal("an unsupported rule was accepted")
	}
	if _, isFieldErr := err.(*Error); isFieldErr {
		t.Error("a bad tag was reported as a client-side violation, not a programming error")
	}
}

// Every tag in internal/models must be one this package implements. Without
// this, adding a rule the validator does not know would turn into a 500 on the
// first request that reaches it, which is how the original finding started:
// tags that read as constraints and enforce nothing.
func TestModelTagsAreAllSupported(t *testing.T) {
	types := []any{
		models.LoginRequest{}, models.ChangePasswordRequest{},
		models.IPListItem{}, models.DomainListItem{}, models.EgressAllowItem{},
		models.InternalAlert{}, models.ImportBlacklistRequest{},
		models.ImportGeoBlacklistRequest{}, models.BulkDeleteRequest{},
	}
	tagged := 0
	for _, v := range types {
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			tag := f.Tag.Get("validate")
			if tag == "" {
				continue
			}
			tagged++
			for _, rule := range strings.Split(tag, ",") {
				verb, arg, _ := strings.Cut(rule, "=")
				switch verb {
				case "required", "omitempty":
				case "min", "max":
					if _, err := bound(arg); err != nil {
						t.Errorf("%s.%s: %v", rt.Name(), f.Name, err)
					}
				case "oneof":
					if len(strings.Fields(arg)) == 0 {
						t.Errorf("%s.%s: oneof with no options", rt.Name(), f.Name)
					}
				default:
					t.Errorf("%s.%s: rule %q is not implemented by this package", rt.Name(), f.Name, rule)
				}
			}
		}
	}
	if tagged == 0 {
		t.Fatal("no validate tags found — the models lost their constraints")
	}
	t.Logf("%d tagged fields checked", tagged)
}
