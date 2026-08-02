package security

import "testing"

func TestCSRFTokenGenerationAndComparison(t *testing.T) {
	firstToken, err := GenerateCSRFToken()
	if err != nil {
		t.Fatalf("GenerateCSRFToken() first error = %v", err)
	}
	secondToken, err := GenerateCSRFToken()
	if err != nil {
		t.Fatalf("GenerateCSRFToken() second error = %v", err)
	}
	if firstToken == secondToken {
		t.Fatal("GenerateCSRFToken() returned duplicate tokens")
	}
	if !CSRFTokenMatches(firstToken, firstToken) {
		t.Fatal("CSRFTokenMatches() rejected matching token")
	}
	if CSRFTokenMatches(firstToken, secondToken) || CSRFTokenMatches(firstToken, "") {
		t.Fatal("CSRFTokenMatches() accepted invalid token")
	}
}
