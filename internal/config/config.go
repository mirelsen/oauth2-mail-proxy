package config

import (
    "io"
    "os"
    "sync"

    "mail-bridge/internal/logging"
    "gopkg.in/yaml.v3"
)

type Listen struct {
    SMTP  string `yaml:"smtp"`
    IMAP  string `yaml:"imap"`
    Admin string `yaml:"admin"`
}

type LocalLogin struct {
    Username string `yaml:"username"`
    Password string `yaml:"password"`
}

type Upstream struct {
    IMAPHost string `yaml:"imap_host"`
    SMTPHost string `yaml:"smtp_host"`
}

type Account struct {
    Label       string     `yaml:"label"`
    Email       string     `yaml:"email"`
    Provider    string     `yaml:"provider"`
    Upstream    Upstream   `yaml:"upstream"`
    LocalLogin  LocalLogin `yaml:"local_login"`
    OAuthRef    string     `yaml:"oauth_ref"`
    Tenant      string     `yaml:"tenant,omitempty"`
}

type Security struct {
    AdminUser         string `yaml:"admin_user"`
    AdminPasswordHash string `yaml:"admin_password_hash"`
    CSRF              bool   `yaml:"csrf"`
    BindLocalOnly     bool   `yaml:"bind_local_only"`
}

type Logging struct {
    Level string `yaml:"level"`
    File  string `yaml:"file"`
}

type Config struct {
    Listen   Listen           `yaml:"listen"`
    Accounts []Account        `yaml:"accounts"`
    Security Security         `yaml:"security"`
    Logging  logging.Config   `yaml:"logging"`
    OAuthApps map[string]OAuthApp `yaml:"oauth_apps"`

    mu sync.RWMutex `yaml:"-"`
    filePath string `yaml:"-"`
}

type OAuthApp struct {
    Provider     string `yaml:"provider"` // gmail | m365
    ClientID     string `yaml:"client_id"`
    ClientSecret string `yaml:"client_secret"`
    RedirectURL  string `yaml:"redirect_url"`
    Tenant       string `yaml:"tenant,omitempty"` // pentru m365
}

func Load(path string) (*Config, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()
    data, err := io.ReadAll(f)
    if err != nil {
        return nil, err
    }
    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }
    // fallback adrese implicite dacă lipsesc
    if cfg.Listen.Admin == "" { cfg.Listen.Admin = "127.0.0.1:7777" }
    if cfg.Listen.IMAP == "" { cfg.Listen.IMAP = "127.0.0.1:1143" }
    if cfg.Listen.SMTP == "" { cfg.Listen.SMTP = "127.0.0.1:1025" }
    cfg.filePath = path
    return &cfg, nil
}

// ReplaceWith înlocuiește în memorie valorile config-ului (folosește mutex pentru cititori).
func (c *Config) ReplaceWith(other *Config) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.Listen = other.Listen
    c.Accounts = other.Accounts
    c.Security = other.Security
    c.Logging = other.Logging
    c.OAuthApps = other.OAuthApps
    if other.filePath != "" { c.filePath = other.filePath }
}

// Snapshot copiază o imagine de moment a config-ului pentru citire fără blocări îndelungate.
func (c *Config) Snapshot() Config {
    c.mu.RLock()
    defer c.mu.RUnlock()
    out := *c
    return out
}

func (c *Config) GetOAuthApp(ref string) (OAuthApp, bool) {
    c.mu.RLock(); defer c.mu.RUnlock()
    if c.OAuthApps == nil { return OAuthApp{}, false }
    app, ok := c.OAuthApps[ref]
    return app, ok
}

// Save persistă config-ul curent în fișierul de unde a fost încărcat.
func (c *Config) Save() error {
    c.mu.RLock()
    defer c.mu.RUnlock()
    if c.filePath == "" { return nil }
    data, err := yaml.Marshal(c)
    if err != nil { return err }
    // permisiuni conservatoare
    return os.WriteFile(c.filePath, data, 0o600)
}

// AppendAccount adaugă un cont și salvează config-ul, folosind lock de scriere.
func (c *Config) AppendAccount(a Account) error {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.Accounts = append(c.Accounts, a)
    if c.filePath == "" { return nil }
    data, err := yaml.Marshal(c)
    if err != nil { return err }
    return os.WriteFile(c.filePath, data, 0o600)
}


