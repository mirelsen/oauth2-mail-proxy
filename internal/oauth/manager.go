package oauth

import (
    "sync"
    "time"

    "mail-bridge/internal/config"
    "mail-bridge/internal/store"
    "fmt"
)

type Manager struct {
    st store.Store
    mu sync.Mutex
}

func NewManager(st store.Store) *Manager {
    return &Manager{st: st}
}

// GetAccessTokenForAccount întoarce un access_token valabil, reîmprospătând dacă este necesar.
func (m *Manager) GetAccessTokenForAccount(acc config.Account) (string, time.Time, error) {
    rec, ok, err := m.st.GetByEmail(acc.Email)
    if err != nil || !ok {
        if err == nil && !ok {
            if list, e := m.st.List(); e == nil {
                emails := make([]string, 0, len(list))
                for _, it := range list { emails = append(emails, it.AccountEmail) }
                return "", time.Time{}, fmt.Errorf("token not found for %s; have: %v", acc.Email, emails)
            }
        }
        return "", time.Time{}, err
    }
    // Dacă valabil încă ≥ 2 minute, returnează-l
    if time.Until(rec.Expiry) > 2*time.Minute && rec.AccessToken != "" {
        return rec.AccessToken, rec.Expiry, nil
    }
    // Reîmprospătare
    m.mu.Lock()
    defer m.mu.Unlock()
    // recitește pentru a evita TOCTOU
    rec, ok, err = m.st.GetByEmail(acc.Email)
    if err != nil || !ok { return "", time.Time{}, err }
    if time.Until(rec.Expiry) > 2*time.Minute && rec.AccessToken != "" {
        return rec.AccessToken, rec.Expiry, nil
    }
    var prov Provider
    switch acc.Provider {
    case "gmail":
        prov = &GoogleProvider{ClientID: rec.ClientID, ClientSecret: rec.ClientSecret, RedirectURL: "http://127.0.0.1:7777/oauth/callback"}
    case "m365":
        prov = &M365Provider{ClientID: rec.ClientID, ClientSecret: rec.ClientSecret, RedirectURL: "http://127.0.0.1:7777/oauth/callback", Tenant: rec.Tenant}
    default:
        return "", time.Time{}, nil
    }
    tok, err := prov.Refresh(rec.RefreshToken)
    if err != nil {
        return "", time.Time{}, err
    }
    // Persistă
    rec.AccessToken = tok.AccessToken
    rec.RefreshToken = rec.RefreshToken // neschimbat de obicei
    rec.Expiry = tok.Expiry
    _ = m.st.Save(rec)
    return rec.AccessToken, rec.Expiry, nil
}


