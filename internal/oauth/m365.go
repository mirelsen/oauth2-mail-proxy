package oauth

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"
)

type M365Provider struct {
    ClientID     string
    ClientSecret string
    RedirectURL  string
    Tenant       string // common | organizations | <tenant-id>
}

func (m *M365Provider) GetAuthURL(state string, emailHint string) (string, error) {
    v := url.Values{}
    scopeHost := "https://outlook.office365.com"
    if strings.EqualFold(m.Tenant, "consumers") { scopeHost = "https://outlook.office.com" }
    v.Set("client_id", m.ClientID)
    v.Set("response_type", "code")
    v.Set("redirect_uri", m.RedirectURL)
    v.Set("scope", scopeHost+"/IMAP.AccessAsUser.All "+scopeHost+"/SMTP.Send offline_access")
    v.Set("response_mode", "query")
    v.Set("prompt", "consent")
    v.Set("state", state)
    if emailHint != "" { v.Set("login_hint", emailHint) }
    return "https://login.microsoftonline.com/" + m.Tenant + "/oauth2/v2.0/authorize?" + v.Encode(), nil
}

func (m *M365Provider) ExchangeCode(code string) (*Token, error) {
    form := url.Values{}
    scopeHost := "https://outlook.office365.com"
    if strings.EqualFold(m.Tenant, "consumers") { scopeHost = "https://outlook.office.com" }
    form.Set("client_id", m.ClientID)
    form.Set("client_secret", m.ClientSecret)
    form.Set("grant_type", "authorization_code")
    form.Set("code", code)
    form.Set("redirect_uri", m.RedirectURL)
    form.Set("scope", scopeHost+"/IMAP.AccessAsUser.All "+scopeHost+"/SMTP.Send offline_access")
    req, _ := http.NewRequest("POST", "https://login.microsoftonline.com/"+m.Tenant+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    resp, err := http.DefaultClient.Do(req)
    if err != nil { return nil, err }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        b, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("m365 exchange status %d: %s", resp.StatusCode, string(b))
    }
    var body struct {
        AccessToken  string `json:"access_token"`
        RefreshToken string `json:"refresh_token"`
        ExpiresIn    int    `json:"expires_in"`
        TokenType    string `json:"token_type"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&body); err != nil { return nil, err }
    if body.AccessToken == "" || body.RefreshToken == "" {
        return nil, fmt.Errorf("m365 exchange missing tokens")
    }
    return &Token{AccessToken: body.AccessToken, RefreshToken: body.RefreshToken, TokenType: body.TokenType, Expiry: time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)}, nil
}

func (m *M365Provider) Refresh(refreshToken string) (*Token, error) {
    form := url.Values{}
    scopeHost := "https://outlook.office365.com"
    if strings.EqualFold(m.Tenant, "consumers") { scopeHost = "https://outlook.office.com" }
    form.Set("client_id", m.ClientID)
    form.Set("client_secret", m.ClientSecret)
    form.Set("grant_type", "refresh_token")
    form.Set("refresh_token", refreshToken)
    form.Set("scope", scopeHost+"/IMAP.AccessAsUser.All "+scopeHost+"/SMTP.Send offline_access")
    req, _ := http.NewRequest("POST", "https://login.microsoftonline.com/"+m.Tenant+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    resp, err := http.DefaultClient.Do(req)
    if err != nil { return nil, err }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        b, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("m365 refresh status %d: %s", resp.StatusCode, string(b))
    }
    var body struct {
        AccessToken string `json:"access_token"`
        ExpiresIn   int    `json:"expires_in"`
        TokenType   string `json:"token_type"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&body); err != nil { return nil, err }
    if body.AccessToken == "" {
        return nil, fmt.Errorf("m365 refresh missing access_token")
    }
    return &Token{AccessToken: body.AccessToken, RefreshToken: refreshToken, TokenType: body.TokenType, Expiry: time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)}, nil
}

func (m *M365Provider) BuildXOAUTH2(email string, accessToken string) (string, error) { return BuildXOAUTH2Blob(email, accessToken) }
func (m *M365Provider) UpstreamHosts() (string, string) { return "outlook.office365.com:993", "smtp.office365.com:587" }


