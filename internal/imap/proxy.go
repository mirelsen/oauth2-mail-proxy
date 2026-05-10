package imap

import (
    "bufio"
    "context"
    "crypto/tls"
    "errors"
    "fmt"
    "io"
    "encoding/base64"
    "log/slog"
    "net"
    "net/textproto"
    "strings"
    "time"

    "mail-bridge/internal/config"
    "mail-bridge/internal/oauth"
)

// Serve pornește listener-ul IMAP și gestionează conexiuni noi.
func Serve(ctx context.Context, lg *slog.Logger, ln net.Listener, cfg *config.Config, om *oauth.Manager) error {
    defer ln.Close()
    for {
        conn, err := ln.Accept()
        if err != nil {
            select {
            case <-ctx.Done():
                return nil
            default:
                lg.Error("IMAP accept eroare", "error", err)
                continue
            }
        }
        go handleClient(ctx, lg, conn, cfg, om)
    }
}

func handleClient(ctx context.Context, lg *slog.Logger, c net.Conn, cfg *config.Config, om *oauth.Manager) {
    defer c.Close()
    rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
    writeLine(rw, "* OK mail-bridge ready")
    for {
        line, err := rw.ReadString('\n')
        if err != nil {
            return
        }
        line = strings.TrimRight(line, "\r\n")
        if line == "" { continue }
        tag, cmd, rest := parseCommand(line)
        upper := strings.ToUpper(cmd)
        switch upper {
        case "CAPABILITY":
            writeLine(rw, "* CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN AUTH=LOGIN")
            writeLine(rw, fmt.Sprintf("%s OK CAPABILITY completed", tag))
        case "NOOP":
            writeLine(rw, fmt.Sprintf("%s OK NOOP completed", tag))
        case "LOGOUT":
            writeLine(rw, "* BYE")
            writeLine(rw, fmt.Sprintf("%s OK LOGOUT completed", tag))
            _ = rw.Flush()
            return
        case "LOGIN":
            username, password := parseLoginArgs(rest)
            if username == "" {
                writeLine(rw, fmt.Sprintf("%s BAD LOGIN args", tag))
                continue
            }
            acc, ok := findAccount(cfg, username, password)
            lg.Info("IMAP local LOGIN", "user", maskEmail(username), "mapped", ok)
            if !ok {
                writeLine(rw, fmt.Sprintf("%s NO authentication failed", tag))
                continue
            }
            if err := upstreamXOAUTHAndPipe(ctx, lg, rw, c, tag, acc, om); err != nil {
                lg.Error("XOAUTH/pipe fail", "error", err, "email", maskEmail(acc.Email))
                return
            }
            return
        case "AUTHENTICATE":
            mech, rest2 := nextAtom(rest)
            mech = strings.ToUpper(mech)
            switch mech {
            case "LOGIN":
                // AUTH LOGIN flow
                writeLine(rw, "+ VXNlcm5hbWU6") // "Username:"
                userB64, err := rw.ReadString('\n')
                if err != nil { return }
                username := decodeB64(strings.TrimSpace(userB64))
                writeLine(rw, "+ UGFzc3dvcmQ6") // "Password:"
                passB64, err := rw.ReadString('\n')
                if err != nil { return }
                password := decodeB64(strings.TrimSpace(passB64))
                acc, ok := findAccount(cfg, username, password)
                lg.Info("IMAP AUTH LOGIN", "user", maskEmail(username), "mapped", ok)
                if !ok {
                    writeLine(rw, fmt.Sprintf("%s NO authentication failed", tag))
                    continue
                }
                if err := upstreamXOAUTHAndPipe(ctx, lg, rw, c, tag, acc, om); err != nil { lg.Error("XOAUTH/pipe fail", "error", err, "email", maskEmail(acc.Email)); return }
                return
            case "PLAIN":
                // PLAIN poate veni cu initial-response sau după +
                ir := strings.TrimSpace(rest2)
                var payload string
                if ir == "" { // așteptăm continuare
                    writeLine(rw, "+ ")
                    pl, err := rw.ReadString('\n')
                    if err != nil { return }
                    payload = strings.TrimSpace(pl)
                } else {
                    payload = ir
                }
                decoded := decodeB64(payload)
                // format: authzid\x00authcid\x00passwd
                parts := strings.Split(decoded, "\x00")
                if len(parts) < 3 {
                    writeLine(rw, fmt.Sprintf("%s BAD AUTHENTICATE PLAIN", tag))
                    continue
                }
                username, password := parts[1], parts[2]
                acc, ok := findAccount(cfg, username, password)
                lg.Info("IMAP AUTH PLAIN", "user", maskEmail(username), "mapped", ok)
                if !ok {
                    writeLine(rw, fmt.Sprintf("%s NO authentication failed", tag))
                    continue
                }
                if err := upstreamXOAUTHAndPipe(ctx, lg, rw, c, tag, acc, om); err != nil { lg.Error("XOAUTH/pipe fail", "error", err, "email", maskEmail(acc.Email)); return }
                return
            default:
                writeLine(rw, fmt.Sprintf("%s NO unsupported mechanism", tag))
            }
        default:
            // înainte de autentificare, răspundem cu BAD
            writeLine(rw, fmt.Sprintf("%s BAD authenticate first", tag))
        }
        _ = rw.Flush()
    }
}

func writeLine(rw *bufio.ReadWriter, s string) { _, _ = rw.WriteString(s + "\r\n"); _ = rw.Flush() }

func parseCommand(line string) (tag, cmd, rest string) {
    sp := strings.SplitN(line, " ", 3)
    tag = sp[0]
    if len(sp) > 1 { cmd = sp[1] }
    if len(sp) > 2 { rest = sp[2] }
    return
}

func parseLoginArgs(rest string) (username, password string) {
    tp := textproto.NewReader(bufio.NewReader(strings.NewReader(rest)))
    // accept formă simplă: username password (posibil quoted)
    // fallback: split simplu dacă parse-ul eșuează
    fields := splitIMAPArgs(rest)
    if len(fields) >= 2 { return unquote(fields[0]), unquote(fields[1]) }
    _ = tp // nefolosit altfel
    return "", ""
}

func splitIMAPArgs(s string) []string {
    var out []string
    cur := strings.Builder{}
    inQuote := false
    esc := false
    for _, r := range s {
        switch {
        case esc:
            cur.WriteRune(r); esc = false
        case r == '\\' && inQuote:
            esc = true
        case r == '"':
            inQuote = !inQuote
        case r == ' ' && !inQuote:
            if cur.Len() > 0 { out = append(out, cur.String()); cur.Reset() }
        default:
            cur.WriteRune(r)
        }
    }
    if cur.Len() > 0 { out = append(out, cur.String()) }
    return out
}

func unquote(s string) string {
    if len(s) >= 2 && strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") { return s[1:len(s)-1] }
    return s
}

func nextAtom(s string) (atom string, rest string) {
    s = strings.TrimSpace(s)
    i := strings.IndexByte(s, ' ')
    if i < 0 { return s, "" }
    return s[:i], s[i+1:]
}

func decodeB64(s string) string { b, err := base64.StdEncoding.DecodeString(s); if err != nil { return "" }; return string(b) }

func findAccount(cfg *config.Config, username, password string) (config.Account, bool) {
    u := strings.TrimSpace(strings.ToLower(username))
    p := password
    snap := cfg.Snapshot()
    for _, a := range snap.Accounts {
        if strings.TrimSpace(strings.ToLower(a.LocalLogin.Username)) == u && a.LocalLogin.Password == p {
            return a, true
        }
    }
    return config.Account{}, false
}

func upstreamXOAUTHAndPipe(ctx context.Context, lg *slog.Logger, rw *bufio.ReadWriter, client net.Conn, clientTag string, acc config.Account, om *oauth.Manager) error {
    // Obține token
    accessToken, _, err := om.GetAccessTokenForAccount(acc)
    if err != nil { writeLine(rw, fmt.Sprintf("%s NO upstream auth failed", clientTag)); return err }
    blob, err := oauth.BuildXOAUTH2Blob(acc.Email, accessToken)
    if err != nil { writeLine(rw, fmt.Sprintf("%s NO xoauth blob failed", clientTag)); return err }
    // Conectare TLS către upstream
    d := &net.Dialer{Timeout: 15 * time.Second}
    tlsConn, err := tls.DialWithDialer(d, "tcp", acc.Upstream.IMAPHost, &tls.Config{ServerName: hostFromAddr(acc.Upstream.IMAPHost)})
    if err != nil { writeLine(rw, fmt.Sprintf("%s NO upstream conn failed", clientTag)); return err }
    // Citește banner
    upstreamR := bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
    banner, _ := upstreamR.ReadString('\n')
    _ = banner // ignorăm bannerul upstream
    // AUTH XOAUTH2
    _, _ = upstreamR.WriteString("A1 AUTHENTICATE XOAUTH2 " + blob + "\r\n")
    _ = upstreamR.Flush()
    // Citește până la tag A1 OK/NO/BAD
    ok := false
    for {
        l, err := upstreamR.ReadString('\n')
        if err != nil { _ = tlsConn.Close(); writeLine(rw, fmt.Sprintf("%s NO upstream read failed", clientTag)); return err }
        line := strings.TrimRight(l, "\r\n")
        if strings.HasPrefix(line, "+ ") { // continuare cerută: trimitem CRLF gol
            _, _ = upstreamR.WriteString("\r\n"); _ = upstreamR.Flush(); continue
        }
        if strings.HasPrefix(line, "A1 ") {
            if strings.Contains(line, " OK ") {
                ok = true
            }
            break
        }
    }
    if !ok {
        _ = tlsConn.Close()
        writeLine(rw, fmt.Sprintf("%s NO authentication failed", clientTag))
        return errors.New("upstream XOAUTH2 failed")
    }
    // Confirmă clientului
    writeLine(rw, fmt.Sprintf("%s OK LOGIN completed", clientTag))
    // Pipe bidirecțional de acum
    // Ce vine de la client -> upstream, și invers
    go func() { _, _ = io.Copy(tlsConn, client); _ = tlsConn.CloseWrite() }()
    _, _ = io.Copy(client, tlsConn)
    return nil
}

func hostFromAddr(addr string) string {
    if h, _, err := net.SplitHostPort(addr); err == nil { return h }
    return addr
}

func maskEmail(s string) string {
    s = strings.TrimSpace(s)
    at := strings.IndexByte(s, '@')
    if at <= 1 { return "***" }
    return s[:1] + "***" + s[at:]
}


