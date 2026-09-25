package onionguard

import "testing"

func FuzzValidateSessionID(f *testing.F) {
	id, _ := GenerateSessionID()
	f.Add(id)
	f.Add("")
	f.Add("abc")
	f.Fuzz(func(t *testing.T, s string) { _ = ValidateSessionID(s) })
}

func FuzzTokenExtraction(f *testing.F) {
	cfg := DefaultConfig()
	f.Add("Bearer abc", "", "")
	f.Fuzz(func(t *testing.T, auth, api, query string) { _ = extractAPITokenRaw(auth, api, query, cfg) })
}

func FuzzChallengeAnswerHash(f *testing.F) {
	f.Add("ABCDE")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) { _ = sha256Bytes(s) })
}
