package store

import "time"

// TokenRecord reprezintă elementul stocat pentru un cont.
type TokenRecord struct {
    AccountEmail string    `json:"account_email"`
    Provider     string    `json:"provider"`
    ClientID     string    `json:"client_id"`
    ClientSecret string    `json:"client_secret,omitempty"`
    RefreshToken string    `json:"refresh_token"` // criptat la stocare
    AccessToken  string    `json:"access_token"`
    Expiry       time.Time `json:"expiry"`
    Tenant       string    `json:"tenant,omitempty"`
    LastLogin    time.Time `json:"last_login"`
}

// Store definește operațiile pentru citire/scriere token-uri.
type Store interface {
    Save(rec TokenRecord) error
    GetByEmail(email string) (TokenRecord, bool, error)
    List() ([]TokenRecord, error)
}


