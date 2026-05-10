package admin

import (
    "crypto/rand"
    "crypto/subtle"
    "encoding/base64"
    "errors"
    "fmt"
    "log/slog"
    "net/http"
    "strings"
    "sync"
    "time"

    "golang.org/x/crypto/argon2"
)

// Sesiuni simple în memorie pentru UI admin.
type session struct {
    id        string
    csrfToken string
    expiresAt time.Time
}

type sessionStore struct {
    mu       sync.Mutex
    sessions map[string]*session
    lg       *slog.Logger
}

func newSessionStore(lg *slog.Logger) *sessionStore {
    return &sessionStore{sessions: make(map[string]*session), lg: lg}
}

func (s *Server) ensureSessionStore() {
    if s.sessions == nil {
        s.sessions = newSessionStore(s.lg)
    }
}

func randBytes(n int) ([]byte, error) {
    b := make([]byte, n)
    _, err := rand.Read(b)
    return b, err
}

func (st *sessionStore) create() (*session, error) {
    idb, err := randBytes(32)
    if err != nil { return nil, err }
    csrfb, err := randBytes(32)
    if err != nil { return nil, err }
    sess := &session{
        id:        base64.RawURLEncoding.EncodeToString(idb),
        csrfToken: base64.RawURLEncoding.EncodeToString(csrfb),
        expiresAt: time.Now().Add(8 * time.Hour),
    }
    st.mu.Lock()
    st.sessions[sess.id] = sess
    st.mu.Unlock()
    return sess, nil
}

func (st *sessionStore) get(id string) (*session, bool) {
    st.mu.Lock()
    defer st.mu.Unlock()
    sess, ok := st.sessions[id]
    if !ok { return nil, false }
    if time.Now().After(sess.expiresAt) {
        delete(st.sessions, id)
        return nil, false
    }
    return sess, true
}

func (st *sessionStore) destroy(id string) { st.mu.Lock(); delete(st.sessions, id); st.mu.Unlock() }

// Argon2id verificare pentru hash în format PHC: $argon2id$v=19$m=...,t=...,p=...$salt$hash
func verifyArgon2idPHC(phc string, password string) (bool, error) {
    if strings.HasPrefix(phc, "plain:") {
        want := strings.TrimPrefix(phc, "plain:")
        if subtle.ConstantTimeCompare([]byte(password), []byte(want)) == 1 { return true, nil }
        return false, nil
    }
    if !strings.HasPrefix(phc, "$argon2id$") {
        return false, errors.New("format hash neacceptat - aștept $argon2id$ sau plain:<parola>")
    }
    parts := strings.Split(phc, "$")
    if len(parts) < 6 { return false, errors.New("hash argon2id invalid") }
    params := parts[3]
    var m, t, p uint32
    _, err := fmt.Sscanf(params, "m=%d,t=%d,p=%d", &m, &t, &p)
    if err != nil { return false, err }
    saltB, err := base64.RawStdEncoding.DecodeString(parts[4])
    if err != nil { return false, err }
    wantHashB, err := base64.RawStdEncoding.DecodeString(parts[5])
    if err != nil { return false, err }
    got := argon2.IDKey([]byte(password), saltB, t, m, uint8(p), uint32(len(wantHashB)))
    if subtle.ConstantTimeCompare(got, wantHashB) == 1 {
        return true, nil
    }
    return false, nil
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Skip pentru login și static
        if r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/static/") || strings.HasPrefix(r.URL.Path, "/oauth/") {
            next.ServeHTTP(w, r)
            return
        }
        s.ensureSessionStore()
        c, err := r.Cookie("mb_session")
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        if _, ok := s.sessions.get(c.Value); !ok {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    s.ensureSessionStore()
    switch r.Method {
    case http.MethodGet:
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        _, _ = w.Write([]byte(`<form method="post"><h2>Login admin</h2><div><label>User <input name="user"></label></div><div><label>Parolă <input name="pass" type="password"></label></div><button type="submit">Login</button></form>`))
    case http.MethodPost:
        _ = r.ParseForm()
        user := r.Form.Get("user")
        pass := r.Form.Get("pass")
        if user == s.cfg.Security.AdminUser {
            ok, err := verifyArgon2idPHC(s.cfg.Security.AdminPasswordHash, pass)
            if err != nil { s.lg.Error("argon2 verify err", "error", err) }
            if ok {
                sess, _ := s.sessions.create()
                cookie := &http.Cookie{Name: "mb_session", Value: sess.id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode}
                http.SetCookie(w, cookie)
                http.Redirect(w, r, "/", http.StatusSeeOther)
                return
            }
        }
        http.Error(w, "Autentificare eșuată", http.StatusUnauthorized)
    default:
        w.WriteHeader(http.StatusMethodNotAllowed)
    }
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
    c, err := r.Cookie("mb_session")
    if err == nil { s.sessions.destroy(c.Value) }
    http.SetCookie(w, &http.Cookie{Name: "mb_session", Value: "", Path: "/", MaxAge: -1})
    http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// OAuth helper
type oauthState struct {
    Ref       string
    Email     string
    CreatedAt time.Time
}

func newRandomState() string {
    b := make([]byte, 24)
    _, _ = rand.Read(b)
    return base64.RawURLEncoding.EncodeToString(b)
}


