package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// The backend passes POST /api/waf/categories/toggle on to this handler, so
// only the WAF can say its request is missing a field. The published OpenAPI
// document describes it as WafCategoryToggle; this holds the handler to that
// schema both ways: a body with every field it requires is taken, the same
// body without one is refused, and a field the schema does not know is not
// refused, because the schema is open.
func TestTheToggleRequestMatchesThePublishedSchema(t *testing.T) {
	raw, err := os.ReadFile("../docs/public/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Required             []string       `json:"required"`
				Properties           map[string]any `json:"properties"`
				AdditionalProperties any            `json:"additionalProperties"` // a bool or, for a map, a schema
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	schema, ok := doc.Components.Schemas["WafCategoryToggle"]
	if !ok {
		t.Fatal("the published document has no WafCategoryToggle")
	}
	if len(schema.Required) == 0 {
		t.Fatal("WafCategoryToggle requires nothing: the test would prove nothing")
	}
	valid := map[string]any{"category": "SQLI", "enabled": false}
	for field := range schema.Properties {
		if _, ok := valid[field]; !ok {
			t.Errorf("WafCategoryToggle has %s, which this test does not send", field)
		}
	}
	post := func(body map[string]any) int {
		b, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		(&MgmtHandlers{}).CategoriesToggleHandler(w, httptest.NewRequest("POST", "/categories/toggle", bytes.NewReader(b)))
		return w.Code
	}
	if code := post(valid); code != http.StatusOK {
		t.Errorf("a body valid by WafCategoryToggle: %d, want 200", code)
	}
	for _, field := range schema.Required {
		without := map[string]any{}
		for k, v := range valid {
			if k != field {
				without[k] = v
			}
		}
		if code := post(without); code != http.StatusBadRequest {
			t.Errorf("without %s, which WafCategoryToggle requires: %d, want 400", field, code)
		}
	}
	extra := map[string]any{"zz_not_a_field": 1}
	for k, v := range valid {
		extra[k] = v
	}
	closed := schema.AdditionalProperties == false
	if code := post(extra); closed && code != http.StatusBadRequest {
		t.Errorf("WafCategoryToggle is closed, and a field it does not know is answered %d", code)
	} else if !closed && code != http.StatusOK {
		t.Errorf("WafCategoryToggle is open, and a field it does not know is answered %d", code)
	}
	// Leave SQLI on for the tests after this one.
	post(map[string]any{"category": "SQLI", "enabled": true})
}
