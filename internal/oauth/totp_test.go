package oauth

import (
	"testing"
	"time"
)

var rfc6238Secret = []byte("12345678901234567890")

func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	cases := map[int64]string{
		59:         "287082",
		1111111109: "081804",
		1234567890: "005924",
		2000000000: "279037",
	}
	for unix, want := range cases {
		if got := totpCode(rfc6238Secret, unix/30); got != want {
			t.Errorf("t=%d: got %s want %s", unix, got, want)
		}
	}
}

func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	now := time.Unix(1111111109, 0)
	step := now.Unix() / 30
	code := totpCode(rfc6238Secret, step)

	if got, ok := verifyTOTP(rfc6238Secret, code, now, 0); !ok || got != step {
		t.Fatalf("current code rejected: step %d ok %t", got, ok)
	}
	if _, ok := verifyTOTP(rfc6238Secret, code, now, step); ok {
		t.Fatal("replayed step accepted")
	}
	prev := totpCode(rfc6238Secret, step-1)
	if _, ok := verifyTOTP(rfc6238Secret, prev, now, 0); !ok {
		t.Fatal("previous-step code should be within drift window")
	}
	far := totpCode(rfc6238Secret, step-5)
	if _, ok := verifyTOTP(rfc6238Secret, far, now, 0); ok {
		t.Fatal("code five steps old accepted")
	}
}
