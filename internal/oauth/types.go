package oauth

import (
    "encoding/base64"
    "fmt"
    "time"
)

// Token reprezintă perechea de token-uri primite de la provider.
type Token struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    Expiry       time.Time `json:"expiry"`
    TokenType    string    `json:"token_type"`
}

// AccountIdentity identifică un cont pentru upstream.
type AccountIdentity struct {
    Email   string
    Tenant  string // pentru m365
    Label   string
    Provider string
}

// Provider interfața care permite plug-in pentru Gmail/M365 etc.
type Provider interface {
    GetAuthURL(state string, emailHint string) (string, error)
    ExchangeCode(code string) (*Token, error)
    Refresh(refreshToken string) (*Token, error)
    BuildXOAUTH2(email string, accessToken string) (string, error)
    UpstreamHosts() (imapTLS string, smtpStartTLS string)
}

// BuildXOAUTH2Blob construiește payload-ul base64 pentru AUTH XOAUTH2.
// Format: base64("user=" + email + "\x01auth=Bearer " + accessToken + "\x01\x01")
func BuildXOAUTH2Blob(email, accessToken string) (string, error) {
    if email == "" || accessToken == "" {
        return "", fmt.Errorf("email/token lipsă pentru XOAUTH2")
    }
    raw := []byte("user=" + email + "\x01auth=Bearer " + accessToken + "\x01\x01")
    return base64.StdEncoding.EncodeToString(raw), nil
}


