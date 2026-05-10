package imap

import (
    "encoding/base64"
    "strings"
    "testing"

    "mail-bridge/internal/oauth"
)

func TestBuildXOAUTH2Blob(t *testing.T) {
    blob, err := oauth.BuildXOAUTH2Blob("user@example.com", "ya29.a0AfH6SMADEUPTOKEN")
    if err != nil { t.Fatalf("err: %v", err) }
    raw, err := base64.StdEncoding.DecodeString(blob)
    if err != nil { t.Fatalf("b64: %v", err) }
    s := string(raw)
    if !strings.Contains(s, "user=user@example.com") { t.Fatalf("missing user: %q", s) }
    if !strings.Contains(s, "auth=Bearer ya29.a0AfH6SMADEUPTOKEN") { t.Fatalf("missing token: %q", s) }
    if !strings.HasSuffix(s, "\x01\x01") { t.Fatalf("missing terminator: %q", s) }
}


