package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	gsmtp "github.com/emersion/go-smtp"
	"mail-bridge/internal/config"
	"mail-bridge/internal/oauth"
)

type backend struct{ lg *slog.Logger; cfg *config.Config; om *oauth.Manager }

func (b *backend) NewSession(state *gsmtp.Conn) (gsmtp.Session, error) {
	return &session{lg: b.lg, cfg: b.cfg, om: b.om}, nil
}

func (b *backend) AnonymousLogin(state *gsmtp.Conn) (gsmtp.Session, error) { return nil, fmt.Errorf("autentificare necesară") }

type session struct {
	lg  *slog.Logger
	cfg *config.Config
	om  *oauth.Manager

	acc  config.Account
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (s *session) AuthPlain(username, password string) error {
	acc, ok := findAccount(s.cfg, username, password)
	if !ok { return fmt.Errorf("autentificare eșuată") }
	s.acc = acc
	return s.connectAndAuth()
}

func (s *session) AuthLogin(username, password string) error { return s.AuthPlain(username, password) }

func (s *session) Mail(from string, opts *gsmtp.MailOptions) error {
	if s.acc.Email == "" {
		if acc, ok := findAccountByEmail(s.cfg, from); ok {
			s.acc = acc
		} else {
			return fmt.Errorf("530 Authentication required")
		}
	}
	if s.conn == nil { if err := s.connectAndAuth(); err != nil { return err } }
	if err := s.sendCmdExpect(250, fmt.Sprintf("MAIL FROM:<%s>", from)); err != nil { _ = s.reauthOnce(); return s.sendCmdExpect(250, fmt.Sprintf("MAIL FROM:<%s>", from)) }
	return nil
}

func (s *session) Rcpt(to string, opts *gsmtp.RcptOptions) error { return s.sendCmdExpectOneOf([]int{250,251}, fmt.Sprintf("RCPT TO:<%s>", to)) }

func (s *session) Data(r io.Reader) error {
	if err := s.sendCmdExpect(354, "DATA"); err != nil { return err }
	if _, err := io.Copy(s.rw, r); err != nil { return err }
	if err := s.rw.Flush(); err != nil { return err }
	if _, err := s.rw.WriteString("\r\n.\r\n"); err != nil { return err }
	if err := s.rw.Flush(); err != nil { return err }
	_, _, err := s.readResponse()
	return err
}

func (s *session) Reset() { }
func (s *session) Logout() error { if s.conn != nil { _ = s.writeLine("QUIT"); _,_,_ = s.readResponse(); _ = s.conn.Close() }; return nil }

func (s *session) connectAndAuth() error {
	// 1) TCP la smtp host:587
	d := &net.Dialer{Timeout: 15 * time.Second}
	c, err := d.Dial("tcp", s.acc.Upstream.SMTPHost)
	if err != nil { return err }
	s.conn = c
	s.rw = bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
	// 2) Citiți banner 220
	code, _, err := s.readResponse()
	if err != nil || code != 220 { s.close(); return fmt.Errorf("smtp banner: %v %d", err, code) }
	// 3) EHLO
	if err := s.sendCmdExpect(250, "EHLO localhost"); err != nil { s.close(); return err }
	// 4) STARTTLS
	if err := s.sendCmdExpect(220, "STARTTLS"); err != nil { s.close(); return err }
	// 5) Wrap TLS
	tlsConn := tls.Client(s.conn, &tls.Config{ServerName: hostFromAddr(s.acc.Upstream.SMTPHost)})
	if err := tlsConn.Handshake(); err != nil { s.close(); return err }
	s.conn = tlsConn
	s.rw = bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
	// 6) EHLO din nou
	if err := s.sendCmdExpect(250, "EHLO localhost"); err != nil { s.close(); return err }
	// 7) AUTH XOAUTH2
	token, _, err := s.om.GetAccessTokenForAccount(s.acc)
	if err != nil { s.close(); return err }
	blob, err := oauth.BuildXOAUTH2Blob(s.acc.Email, token)
	if err != nil { s.close(); return err }
	if err := s.authXOAUTH2(blob); err != nil { s.close(); return err }
	return nil
}

func (s *session) authXOAUTH2(blob string) error {
	if err := s.writeLine("AUTH XOAUTH2 " + blob); err != nil { return err }
	for {
		code, line, err := s.readResponse()
		if err != nil { return err }
		switch code {
		case 235:
			return nil
		case 334:
			// challenge -> trimite CRLF gol
			_ = s.writeLine("")
			continue
		case 535:
			return errors.New("auth 535")
		default:
			return fmt.Errorf("auth resp %d %s", code, line)
		}
	}
}

func (s *session) reauthOnce() error {
	token, _, err := s.om.GetAccessTokenForAccount(s.acc)
	if err != nil { return err }
	blob, err := oauth.BuildXOAUTH2Blob(s.acc.Email, token)
	if err != nil { return err }
	return s.authXOAUTH2(blob)
}

func (s *session) writeLine(line string) error { _, err := s.rw.WriteString(line + "\r\n"); if err != nil { return err }; return s.rw.Flush() }

func (s *session) sendCmdExpect(expect int, cmd string) error {
	if err := s.writeLine(cmd); err != nil { return err }
	code, _, err := s.readResponse()
	if err != nil { return err }
	if code != expect { return fmt.Errorf("resp %d, aștept %d", code, expect) }
	return nil
}

func (s *session) sendCmdExpectOneOf(expects []int, cmd string) error {
	if err := s.writeLine(cmd); err != nil { return err }
	code, _, err := s.readResponse()
	if err != nil { return err }
	for _, e := range expects { if code == e { return nil } }
	return fmt.Errorf("resp %d, aștept %v", code, expects)
}

func (s *session) readResponse() (int, string, error) {
	// SMTP poate trimite linii multiple: "250-...", ultima e "250 ..."
	var last string
	for {
		l, err := s.rw.ReadString('\n')
		if err != nil { return 0, "", err }
		line := strings.TrimRight(l, "\r\n")
		last = line
		if len(line) >= 4 {
			code, _ := strconv.Atoi(line[:3])
			if line[3] == ' ' { return code, line, nil }
			if line[3] == '-' { continue }
		}
		// fallback
		break
	}
	return 0, last, nil
}

func (s *session) close() error { if s.conn != nil { _ = s.conn.Close(); s.conn = nil }; return nil }

func findAccount(cfg *config.Config, username, password string) (config.Account, bool) {
	snap := cfg.Snapshot()
	for _, a := range snap.Accounts {
		if a.LocalLogin.Username == username && a.LocalLogin.Password == password {
			return a, true
		}
	}
	return config.Account{}, false
}

func findAccountByEmail(cfg *config.Config, email string) (config.Account, bool) {
    e := strings.TrimSpace(strings.ToLower(strings.Trim(email, "<>")))
    if i := strings.LastIndex(e, "<"); i >= 0 {
        if j := strings.Index(e[i+1:], ">"); j > 0 { e = e[i+1:i+1+j] }
    }
    snap := cfg.Snapshot()
    for _, a := range snap.Accounts {
        if strings.TrimSpace(strings.ToLower(a.Email)) == e {
            return a, true
        }
    }
    return config.Account{}, false
}

// Serve pornește serverul SMTP local
func Serve(ctx context.Context, lg *slog.Logger, cfg *config.Config, om *oauth.Manager) error {
	be := &backend{lg: lg, cfg: cfg, om: om}
	s := gsmtp.NewServer(be)
	s.Addr = cfg.Listen.SMTP
	s.Domain = "localhost"
	s.AllowInsecureAuth = true

	go func() { <-ctx.Done(); _ = s.Close() }()
	lg.Info("SMTP proxy ascultă", "addr", s.Addr)
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil { return err }
	return s.Serve(ln)
}

func hostFromAddr(addr string) string {
    if h, _, err := net.SplitHostPort(addr); err == nil { return h }
    return addr
}


