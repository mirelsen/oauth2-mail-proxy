package oauth

import (
    "encoding/json"
    "fmt"
    "io"
    "net/url"
    "net/http"
    "strings"
    "time"
)

type GoogleProvider struct {
    ClientID     string
    ClientSecret string
    RedirectURL  string // http://127.0.0.1:7777/oauth/callback
}

func (g *GoogleProvider) GetAuthURL(state string, emailHint string) (string, error) {
    v := url.Values{}
    v.Set("client_id", g.ClientID)
    v.Set("redirect_uri", g.RedirectURL)
    v.Set("response_type", "code")
    v.Set("scope", "https://mail.google.com/")
    v.Set("access_type", "offline")
    v.Set("prompt", "consent")
    v.Set("state", state)
    if emailHint != "" { v.Set("login_hint", emailHint) }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + v.Encode(), nil
}

func (g *GoogleProvider) ExchangeCode(code string) (*Token, error) {
    form := url.Values{}
    form.Set("client_id", g.ClientID)
    form.Set("client_secret", g.ClientSecret)
    form.Set("code", code)
    form.Set("grant_type", "authorization_code")
    form.Set("redirect_uri", g.RedirectURL)
    req, _ := http.NewRequest("POST", "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    resp, err := http.DefaultClient.Do(req)
    if err != nil { return nil, err }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        b, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("google exchange status %d: %s", resp.StatusCode, string(b))
    }
    var body struct {
        AccessToken  string `json:"access_token"`
        RefreshToken string `json:"refresh_token"`
        ExpiresIn    int    `json:"expires_in"`
        TokenType    string `json:"token_type"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&body); err != nil { return nil, err }
    if body.AccessToken == "" || body.RefreshToken == "" {
        return nil, fmt.Errorf("google exchange missing tokens")
    }
    return &Token{AccessToken: body.AccessToken, RefreshToken: body.RefreshToken, TokenType: body.TokenType, Expiry: time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)}, nil
}

func (g *GoogleProvider) Refresh(refreshToken string) (*Token, error) {
    form := url.Values{}
    form.Set("client_id", g.ClientID)
    form.Set("client_secret", g.ClientSecret)
    form.Set("grant_type", "refresh_token")
    form.Set("refresh_token", refreshToken)
    req, _ := http.NewRequest("POST", "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    resp, err := http.DefaultClient.Do(req)
    if err != nil { return nil, err }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        b, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("google refresh status %d: %s", resp.StatusCode, string(b))
    }
    var body struct {
        AccessToken string `json:"access_token"`
        ExpiresIn   int    `json:"expires_in"`
        TokenType   string `json:"token_type"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&body); err != nil { return nil, err }
    if body.AccessToken == "" {
        return nil, fmt.Errorf("google refresh missing access_token")
    }
    return &Token{AccessToken: body.AccessToken, RefreshToken: refreshToken, TokenType: body.TokenType, Expiry: time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)}, nil
}

func (g *GoogleProvider) BuildXOAUTH2(email string, accessToken string) (string, error) { return BuildXOAUTH2Blob(email, accessToken) }
func (g *GoogleProvider) UpstreamHosts() (string, string) { return "imap.gmail.com:993", "smtp.gmail.com:587" }


