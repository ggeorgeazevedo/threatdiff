package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseNestedMappingAndSequence(t *testing.T) {
	src := `
version: 1
name: demo         # trailing comment
rules:
  - id: a.b
    severity: high
    patterns:
      - 'foo: bar'
      - "baz"
    enabled: false
  - id: c.d
    languages: [go, python]
`
	got, err := parseYAML(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("root is %T", got)
	}
	if m["version"] != int64(1) {
		t.Errorf("version = %#v", m["version"])
	}
	if m["name"] != "demo" {
		t.Errorf("name = %#v", m["name"])
	}
	list, ok := m["rules"].([]any)
	if !ok || len(list) != 2 {
		t.Fatalf("rules = %#v", m["rules"])
	}
	first := list[0].(map[string]any)
	if first["id"] != "a.b" || first["severity"] != "high" || first["enabled"] != false {
		t.Errorf("first rule = %#v", first)
	}
	pats := first["patterns"].([]any)
	// A colon inside a quoted scalar must not be read as a mapping separator.
	if len(pats) != 2 || pats[0] != "foo: bar" || pats[1] != "baz" {
		t.Errorf("patterns = %#v", pats)
	}
	second := list[1].(map[string]any)
	if !reflect.DeepEqual(second["languages"], []any{"go", "python"}) {
		t.Errorf("languages = %#v", second["languages"])
	}
}

func TestSequenceAtSameIndentAsKey(t *testing.T) {
	src := `
paths:
- one
- two
other: 3
`
	got, err := parseYAML(src)
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if !reflect.DeepEqual(m["paths"], []any{"one", "two"}) {
		t.Errorf("paths = %#v", m["paths"])
	}
	if m["other"] != int64(3) {
		t.Errorf("other = %#v", m["other"])
	}
}

func TestBlockScalars(t *testing.T) {
	src := "literal: |\n" +
		"  line one\n" +
		"    indented\n" +
		"  line three\n" +
		"folded: >\n" +
		"  wrapped over\n" +
		"  two lines\n" +
		"strip: |-\n" +
		"  no trailing newline\n" +
		"after: yes\n"
	got, err := parseYAML(src)
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["literal"] != "line one\n  indented\nline three\n" {
		t.Errorf("literal = %q", m["literal"])
	}
	if m["folded"] != "wrapped over two lines\n" {
		t.Errorf("folded = %q", m["folded"])
	}
	if m["strip"] != "no trailing newline" {
		t.Errorf("strip = %q", m["strip"])
	}
	if m["after"] != true {
		t.Errorf("after = %#v", m["after"])
	}
}

func TestScalarTypes(t *testing.T) {
	cases := map[string]any{
		"42":      int64(42),
		"-7":      int64(-7),
		"3.5":     3.5,
		"true":    true,
		"False":   false,
		"null":    nil,
		"~":       nil,
		"'42'":    "42",
		`"hi\n"`:  "hi\n",
		"plain":   "plain",
		"v1.2.3":  "v1.2.3",
		"[a, 1]":  []any{"a", int64(1)},
		"{a: 1}":  map[string]any{"a": int64(1)},
		"'it''s'": "it's",
	}
	for in, want := range cases {
		got, err := parseScalar(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q -> %#v, want %#v", in, got, want)
		}
	}
}

func TestCommentStripping(t *testing.T) {
	cases := map[string]string{
		`value # comment`:      `value`,
		`'a # b'`:              `'a # b'`,
		`"x#y" # real comment`: `"x#y"`,
		`url#fragment`:         `url#fragment`,
		`# whole line`:         ``,
	}
	for in, want := range cases {
		if got := stripComment(in); got != want {
			t.Errorf("stripComment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRejectsUnsupportedAndBadInput(t *testing.T) {
	// A rule file that cannot be understood must fail loudly. Silently
	// misparsing a security rule is how a check gets disabled by accident.
	cases := map[string]string{
		"anchors":        "a: &anchor 1\n",
		"aliases":        "a: *anchor\n",
		"tags":           "a: !!str 1\n",
		"tab indent":     "a:\n\tb: 1\n",
		"duplicate keys": "a: 1\na: 2\n",
		"not a mapping":  "a: 1\n  oops: 2\n",
		"multi document": "a: 1\n---\nb: 2\n",
	}
	for name, src := range cases {
		if _, err := parseYAML(src); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestUnmarshalYAMLIntoStruct(t *testing.T) {
	type inner struct {
		Enabled *bool `json:"enabled,omitempty"`
		Level   int   `json:"level,omitempty"`
	}
	type outer struct {
		Name  string   `json:"name"`
		Tags  []string `json:"tags,omitempty"`
		Inner inner    `json:"inner,omitempty"`
	}
	var got outer
	src := "name: x\ntags: [a, b]\ninner:\n  enabled: false\n  level: 4\n"
	if err := UnmarshalYAML([]byte(src), &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "x" || len(got.Tags) != 2 || got.Inner.Level != 4 {
		t.Fatalf("got %+v", got)
	}
	if got.Inner.Enabled == nil || *got.Inner.Enabled {
		t.Errorf("enabled = %v, want explicit false", got.Inner.Enabled)
	}
}

func TestUnmarshalYAMLRejectsUnknownField(t *testing.T) {
	type s struct {
		Known string `json:"known"`
	}
	var got s
	err := UnmarshalYAML([]byte("known: a\nunkown: b\n"), &got)
	if err == nil {
		t.Fatal("expected an error for the typo'd field")
	}
	if !strings.Contains(err.Error(), "unkown") {
		t.Errorf("error should name the offending field, got: %v", err)
	}
}

func TestErrorsCarryLineNumbers(t *testing.T) {
	_, err := parseYAML("a: 1\nb: &x 2\n")
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("want a line-2 error, got %v", err)
	}
}
