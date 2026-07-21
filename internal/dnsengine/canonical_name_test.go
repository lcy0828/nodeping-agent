package dnsengine

import "testing"

func TestCanonicalNameOnlyFoldsASCIILetters(t *testing.T) {
	if got := canonicalName("A.\u00c4.EXAMPLE"); got != "a.\u00c4.example." {
		t.Fatalf("canonicalName() = %q, want ASCII-only case folding", got)
	}
}
