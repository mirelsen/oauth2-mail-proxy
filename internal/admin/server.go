package admin

import (
    "bufio"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "html/template"
    "io"
    "io/fs"
    "log/slog"
    "net"
    "net/http"
    "strconv"
    "strings"
    "time"

    "mail-bridge/internal/config"
    "mail-bridge/internal/store"
    "mail-bridge/internal/oauth"
    "mail-bridge/web"
)


type Server struct {
    lg   *slog.Logger
    cfg  *config.Config
    tmpl *template.Template
    sessions *sessionStore
    st   store.Store
    oauthStates map[string]oauthState
    om   *oauth.Manager
}

func NewServer(lg *slog.Logger, cfg *config.Config, st store.Store, om *oauth.Manager) http.Handler {
    s := &Server{lg: lg, cfg: cfg, st: st, oauthStates: make(map[string]oauthState), om: om}
    s.tmpl = template.Must(template.New("base").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>mail-bridge</title></head><body>{{ template "content" . }}</body></html>`))
    mux := http.NewServeMux()

    mux.HandleFunc("/", s.handleIndex)
    mux.HandleFunc("/login", s.handleLogin)    // declarată în auth.go
    mux.HandleFunc("/logout", s.handleLogout)  // declarată în auth.go
    mux.HandleFunc("/oauth/start", s.handleOAuthStart)
    mux.HandleFunc("/oauth/callback", s.handleOAuthCallback)
    mux.HandleFunc("/api/accounts", s.handleAPIAccounts)
    mux.HandleFunc("/api/test/imap", s.handleTestIMAP)
    mux.HandleFunc("/api/test/smtp", s.handleTestSMTP)
    mux.HandleFunc("/api/providers", s.handleAPIProviders)
    mux.HandleFunc("/api/accounts/create", s.handleAPIAccountsPost)
    // Servește /static/* din web/static
    sub, err := fs.Sub(web.StaticFS, "static")
    if err == nil {
        staticFS := http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
        mux.Handle("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("Cache-Control", "no-store")
            staticFS.ServeHTTP(w, r)
        }))
    } else {
        lg.Error("Nu pot monta web/static", "error", err)
    }

    return s.withSecurityHeaders(s.requireAuth(mux))
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        if strings.HasPrefix(r.Host, "127.0.0.1:") || strings.HasPrefix(r.Host, "localhost:") {
            // Cookie Secure poate fi opțional în dev; HSTS omis
        }
        next.ServeHTTP(w, r)
    })
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
    // redirecționează către UI static
    http.Redirect(w, r, "/static/index.html", http.StatusSeeOther)
}

// handleLogin/handleLogout sunt implementate în auth.go

func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
    // /oauth/start?provider=gmail&ref=gmail-personal&email=user@gmail.com
    q := r.URL.Query()
    ref := q.Get("ref")
    email := q.Get("email")
    if email == "" { http.Error(w, "parametri lipsa", http.StatusBadRequest); return }
    if ref == "" {
        // Derivă din cont, după email
        if acc, ok := findAccountByEmail(s.cfg, email); ok {
            ref = acc.OAuthRef
        }
    }
    if ref == "" { http.Error(w, "parametri lipsa", http.StatusBadRequest); return }
    app, ok := s.cfg.GetOAuthApp(ref)
    if !ok { http.Error(w, "oauth ref invalid", http.StatusBadRequest); return }
    prov := providerFromApp(app)
    state := newRandomState()
    s.oauthStates[state] = oauthState{Ref: ref, Email: email, CreatedAt: time.Now()}
    url, err := prov.GetAuthURL(state, email)
    if err != nil { http.Error(w, "nu pot genera url", http.StatusInternalServerError); return }
    http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query()
    state := q.Get("state")
    code := q.Get("code")
    if state == "" || code == "" { http.Error(w, "parametri lipsa", http.StatusBadRequest); return }
    st, ok := s.oauthStates[state]
    if !ok { http.Error(w, "state invalid", http.StatusBadRequest); return }
    delete(s.oauthStates, state)
    app, ok := s.cfg.GetOAuthApp(st.Ref)
    if !ok { http.Error(w, "oauth ref invalid", http.StatusBadRequest); return }
    prov := providerFromApp(app)
    tok, err := prov.ExchangeCode(code)
    if err != nil { http.Error(w, "exchange esuat: "+err.Error(), http.StatusBadGateway); return }
    // Persistă token-urile
    rec := store.TokenRecord{
        AccountEmail: st.Email,
        Provider:     app.Provider,
        ClientID:     app.ClientID,
        ClientSecret: app.ClientSecret,
        RefreshToken: tok.RefreshToken,
        AccessToken:  tok.AccessToken,
        Expiry:       tok.Expiry,
        Tenant:       app.Tenant,
        LastLogin:    time.Now(),
    }
    if err := s.st.Save(rec); err != nil {
        s.lg.Error("persist esuat", "error", err)
        http.Error(w, "persist esuat: "+err.Error(), http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "email": st.Email, "provider": app.Provider})
}

// Teste API
func (s *Server) handleTestIMAP(w http.ResponseWriter, r *http.Request) {
    email := r.URL.Query().Get("email")
    if email == "" { http.Error(w, "email lipsa", http.StatusBadRequest); return }
    acc, ok := findAccountByEmail(s.cfg, email)
    if !ok { http.Error(w, "cont negasit", http.StatusBadRequest); return }
    token, _, err := s.om.GetAccessTokenForAccount(acc)
    if err != nil { http.Error(w, "token fail: "+err.Error(), http.StatusBadGateway); return }
    blob, err := oauth.BuildXOAUTH2Blob(acc.Email, token)
    if err != nil { http.Error(w, "xoauth2 fail", http.StatusInternalServerError); return }
    // Conectează la IMAP TLS
    conn, err := tls.Dial("tcp", acc.Upstream.IMAPHost, &tls.Config{ServerName: hostFromAddr(acc.Upstream.IMAPHost)})
    if err != nil { http.Error(w, "connect fail: "+err.Error(), http.StatusBadGateway); return }
    defer conn.Close()
    rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
    // banner
    _, _ = rw.ReadString('\n')
    // AUTHENTICATE XOAUTH2
    _, _ = rw.WriteString("A1 AUTHENTICATE XOAUTH2 "+blob+"\r\n"); _ = rw.Flush()
    if ok, err := imapReadUntilTag(rw, "A1"); err != nil || !ok { http.Error(w, "auth fail", http.StatusBadGateway); return }
    // SELECT INBOX
    _, _ = rw.WriteString("A2 SELECT INBOX\r\n"); _ = rw.Flush()
    exists, err := imapReadSelectExists(rw, "A2")
    if err != nil { http.Error(w, "select fail", http.StatusBadGateway); return }
    start := 1
    if exists > 10 { start = exists - 9 }
    // FETCH subjects
    _, _ = rw.WriteString(fmt.Sprintf("A3 FETCH %d:%d (BODY.PEEK[HEADER.FIELDS (SUBJECT)])\r\n", start, exists)); _ = rw.Flush()
    subjects, err := imapReadSubjects(rw, "A3")
    if err != nil { http.Error(w, "fetch fail", http.StatusBadGateway); return }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": len(subjects), "subjects": subjects})
}

func (s *Server) handleTestSMTP(w http.ResponseWriter, r *http.Request) {
    email := r.URL.Query().Get("email")
    if email == "" { http.Error(w, "email lipsa", http.StatusBadRequest); return }
    acc, ok := findAccountByEmail(s.cfg, email)
    if !ok { http.Error(w, "cont negasit", http.StatusBadRequest); return }
    token, _, err := s.om.GetAccessTokenForAccount(acc)
    if err != nil { http.Error(w, "token fail: "+err.Error(), http.StatusBadGateway); return }
    blob, err := oauth.BuildXOAUTH2Blob(acc.Email, token)
    if err != nil { http.Error(w, "xoauth2 fail", http.StatusInternalServerError); return }
    // Connect + STARTTLS + XOAUTH2
    d := &net.Dialer{Timeout: 15 * time.Second}
    c, err := d.Dial("tcp", acc.Upstream.SMTPHost)
    if err != nil { http.Error(w, "connect fail: "+err.Error(), http.StatusBadGateway); return }
    rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
    // banner
    if code, _, err := smtpReadResp(rw); err != nil || code != 220 { _ = c.Close(); http.Error(w, "banner fail", http.StatusBadGateway); return }
    if err := smtpCmdExpect(rw, 250, "EHLO localhost"); err != nil { _ = c.Close(); http.Error(w, "ehlo fail", http.StatusBadGateway); return }
    if err := smtpCmdExpect(rw, 220, "STARTTLS"); err != nil { _ = c.Close(); http.Error(w, "starttls fail", http.StatusBadGateway); return }
    tlsConn := tls.Client(c, &tls.Config{ServerName: hostFromAddr(acc.Upstream.SMTPHost)})
    if err := tlsConn.Handshake(); err != nil { _ = c.Close(); http.Error(w, "tls fail", http.StatusBadGateway); return }
    rw = bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
    if err := smtpCmdExpect(rw, 250, "EHLO localhost"); err != nil { _ = tlsConn.Close(); http.Error(w, "ehlo2 fail", http.StatusBadGateway); return }
    if err := smtpAuthXOAUTH2(rw, blob); err != nil { _ = tlsConn.Close(); http.Error(w, "auth fail: "+err.Error(), http.StatusBadGateway); return }
    // MAIL/RCPT/DATA
    if err := smtpCmdExpect(rw, 250, fmt.Sprintf("MAIL FROM:<%s>", acc.Email)); err != nil { _ = tlsConn.Close(); http.Error(w, "mail fail", http.StatusBadGateway); return }
    if err := smtpCmdExpectOne(rw, []int{250,251}, fmt.Sprintf("RCPT TO:<%s>", acc.Email)); err != nil { _ = tlsConn.Close(); http.Error(w, "rcpt fail", http.StatusBadGateway); return }
    if err := smtpCmdExpect(rw, 354, "DATA"); err != nil { _ = tlsConn.Close(); http.Error(w, "data fail", http.StatusBadGateway); return }
    now := time.Now().Format(time.RFC1123Z)
    msg := fmt.Sprintf("Date: %s\r\nFrom: %s\r\nTo: %s\r\nSubject: mail-bridge test\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSalut! Acesta este un mesaj de test trimis de mail-bridge.\r\n", now, acc.Email, acc.Email)
    _, _ = io.WriteString(rw, msg)
    _, _ = rw.WriteString("\r\n.\r\n"); _ = rw.Flush()
    if _, _, err := smtpReadResp(rw); err != nil { _ = tlsConn.Close(); http.Error(w, "post-data fail", http.StatusBadGateway); return }
    _ = rw.WriteByte('.'); _ = tlsConn.Close()
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// API: listă conturi + status token
func (s *Server) handleAPIAccounts(w http.ResponseWriter, r *http.Request) {
    snap := s.cfg.Snapshot()
    type item struct {
        Label string `json:"label"`
        Email string `json:"email"`
        Provider string `json:"provider"`
        HasToken bool `json:"has_token"`
        Expiry string `json:"expiry"`
        OAuthRef string `json:"oauth_ref"`
    }
    var out []item
    list, _ := s.st.List()
    for _, a := range snap.Accounts {
        it := item{Label: a.Label, Email: a.Email, Provider: a.Provider, OAuthRef: a.OAuthRef}
        for _, t := range list {
            if strings.EqualFold(t.AccountEmail, a.Email) {
                it.HasToken = t.RefreshToken != "" || t.AccessToken != ""
                if !t.Expiry.IsZero() { it.Expiry = t.Expiry.Format(time.RFC3339) }
                break
            }
        }
        out = append(out, it)
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleAPIProviders(w http.ResponseWriter, r *http.Request) {
    snap := s.cfg.Snapshot()
    out := make(map[string]config.OAuthApp)
    for k, v := range snap.OAuthApps { out[k] = v }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleAPIAccountsPost(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost { w.WriteHeader(http.StatusMethodNotAllowed); return }
    var body struct {
        Label string `json:"label"`
        Email string `json:"email"`
        Provider string `json:"provider"`
        OAuthRef string `json:"oauth_ref"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil { http.Error(w, "json", http.StatusBadRequest); return }
    if body.Label == "" || body.Email == "" || body.Provider == "" || body.OAuthRef == "" {
        http.Error(w, "campuri lipsa", http.StatusBadRequest); return
    }
    // upstream defaults per provider
    up := config.Upstream{}
    switch body.Provider {
    case "gmail":
        up.IMAPHost = "imap.gmail.com:993"; up.SMTPHost = "smtp.gmail.com:587"
    case "m365":
        up.IMAPHost = "outlook.office365.com:993"; up.SMTPHost = "smtp.office365.com:587"
    default:
        http.Error(w, "provider necunoscut", http.StatusBadRequest); return
    }
    acc := config.Account{Label: body.Label, Email: body.Email, Provider: body.Provider, Upstream: up, OAuthRef: body.OAuthRef, LocalLogin: config.LocalLogin{Username: body.Email, Password: "anything"}}
    // adaugă în config și salvează
    _ = s.cfg.AppendAccount(acc)
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// Helpers
func findAccountByEmail(cfg *config.Config, email string) (config.Account, bool) {
    e := strings.TrimSpace(strings.ToLower(email))
    snap := cfg.Snapshot()
    for _, a := range snap.Accounts {
        if strings.EqualFold(strings.TrimSpace(a.Email), e) {
            return a, true
        }
    }
    return config.Account{}, false
}

func hostFromAddr(addr string) string {
    if h, _, err := net.SplitHostPort(addr); err == nil { return h }
    return addr
}

func imapReadUntilTag(rw *bufio.ReadWriter, tag string) (bool, error) {
    for {
        l, err := rw.ReadString('\n')
        if err != nil { return false, err }
        line := strings.TrimRight(l, "\r\n")
        if strings.HasPrefix(line, tag+" ") {
            return strings.Contains(line, " OK "), nil
        }
    }
}

func imapReadSelectExists(rw *bufio.ReadWriter, tag string) (int, error) {
    exists := 0
    for {
        l, err := rw.ReadString('\n')
        if err != nil { return 0, err }
        line := strings.TrimRight(l, "\r\n")
        if strings.HasPrefix(line, "*") && strings.Contains(line, " EXISTS") {
            // format: * <n> EXISTS
            f := strings.Fields(line)
            if len(f) >= 2 { if n, e := strconv.Atoi(f[1]); e == nil { exists = n } }
        }
        if strings.HasPrefix(line, tag+" ") {
            if !strings.Contains(line, " OK ") { return 0, fmt.Errorf("select not ok") }
            return exists, nil
        }
    }
}

func imapReadSubjects(rw *bufio.ReadWriter, tag string) ([]string, error) {
    var out []string
    for {
        l, err := rw.ReadString('\n')
        if err != nil { return nil, err }
        line := strings.TrimRight(l, "\r\n")
        if strings.HasPrefix(strings.ToLower(line), "subject:") {
            out = append(out, strings.TrimSpace(line[8:]))
        }
        if strings.HasPrefix(line, tag+" ") {
            if !strings.Contains(line, " OK ") { return nil, fmt.Errorf("fetch not ok") }
            return out, nil
        }
    }
}

func smtpReadResp(rw *bufio.ReadWriter) (int, string, error) {
    var last string
    for {
        l, err := rw.ReadString('\n')
        if err != nil { return 0, "", err }
        line := strings.TrimRight(l, "\r\n")
        last = line
        if len(line) >= 4 {
            if n, err := strconv.Atoi(line[:3]); err == nil {
                if line[3] == ' ' { return n, line, nil }
                if line[3] == '-' { continue }
            }
        }
        break
    }
    return 0, last, nil
}

func smtpCmdExpect(rw *bufio.ReadWriter, code int, cmd string) error {
    _, _ = rw.WriteString(cmd+"\r\n"); _ = rw.Flush()
    got, _, err := smtpReadResp(rw)
    if err != nil { return err }
    if got != code { return fmt.Errorf("smtp expect %d got %d", code, got) }
    return nil
}

func smtpCmdExpectOne(rw *bufio.ReadWriter, codes []int, cmd string) error {
    _, _ = rw.WriteString(cmd+"\r\n"); _ = rw.Flush()
    got, _, err := smtpReadResp(rw)
    if err != nil { return err }
    for _, c := range codes { if c == got { return nil } }
    return fmt.Errorf("smtp expect one of %v got %d", codes, got)
}

func smtpAuthXOAUTH2(rw *bufio.ReadWriter, blob string) error {
    _, _ = rw.WriteString("AUTH XOAUTH2 "+blob+"\r\n"); _ = rw.Flush()
    for {
        code, _, err := smtpReadResp(rw)
        if err != nil { return err }
        switch code {
        case 235:
            return nil
        case 334:
            // empty response
            _, _ = rw.WriteString("\r\n"); _ = rw.Flush()
        default:
            return fmt.Errorf("auth code %d", code)
        }
    }
}

func providerFromApp(app config.OAuthApp) oauth.Provider {
	switch app.Provider {
	case "gmail":
		return &oauth.GoogleProvider{ClientID: app.ClientID, ClientSecret: app.ClientSecret, RedirectURL: app.RedirectURL}
	case "m365":
		return &oauth.M365Provider{ClientID: app.ClientID, ClientSecret: app.ClientSecret, RedirectURL: app.RedirectURL, Tenant: app.Tenant}
	default:
		return &oauth.GoogleProvider{ClientID: app.ClientID, ClientSecret: app.ClientSecret, RedirectURL: app.RedirectURL}
	}
}


