package main

import (
    "crypto/rand"
    "encoding/base64"
    "flag"
    "fmt"
    "os"
    "time"

    "golang.org/x/crypto/argon2"
)

func main() {
    var password string
    flag.StringVar(&password, "p", "", "Parola de hashu-it (sau primul argument)")
    flag.Parse()
    if password == "" {
        if flag.NArg() >= 1 { password = flag.Arg(0) }
    }
    if password == "" {
        fmt.Fprintln(os.Stderr, "Folosește: go run ./cmd/hashpw --p <parola>")
        os.Exit(2)
    }
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil { panic(err) }
    // Parametri rezonabili pentru desktop: t=3, m=64MB, p=2, out=32
    t, m, p := uint32(3), uint32(64*1024), uint8(2)
    start := time.Now()
    dk := argon2.IDKey([]byte(password), salt, t, m, p, 32)
    _ = start
    // PHC: $argon2id$v=19$m=65536,t=3,p=2$<salt_b64>$<hash_b64>
    saltB64 := base64.RawStdEncoding.EncodeToString(salt)
    dkB64 := base64.RawStdEncoding.EncodeToString(dk)
    fmt.Printf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s\n", m, t, p, saltB64, dkB64)
}


