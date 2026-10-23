package main

import (
	"os"
	"regexp"
	"testing"
)

func TestGenerateIsDeterministicAndComplete(t *testing.T) {
	data, err := os.ReadFile("../../docs/rbac/permission-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	a, err := Generate(data)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(data)
	if err != nil || string(a) != string(b) {
		t.Fatal("generation must be deterministic")
	}
	src := string(a)
	for _, want := range []string{`DO NOT EDIT`, `"workspace.transfer_ownership":\s+\{Kind: Write, Scope: WorkspaceScope, Administrative: true, Sensitive: true, OwnerOnly: true\}`, `"tester": \{`, `"repository.delete":\s+Own`, `"viewer":\s+Read`} {
		if !regexp.MustCompile(want).MatchString(src) {
			t.Fatalf("generated source lacks %q", want)
		}
	}
}

func TestGenerateRejectsInvalidCatalogs(t *testing.T) {
	for name, data := range map[string]string{
		"not json":       "{",
		"bad kind":       `{"permissions":[{"id":"a.b","kind":"fly","scope":"workspace"}]}`,
		"bad condition":  `{"permissions":[{"id":"a.b","kind":"read","scope":"workspace"}],"roles":[{"id":"owner","grants":{"a.b":"sometimes"}}]}`,
		"bad level kind": `{"projectAccessLevels":[{"id":"viewer","maxKind":"admin"}]}`,
	} {
		if _, err := Generate([]byte(data)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
