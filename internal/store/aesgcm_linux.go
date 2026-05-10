//go:build linux

package store

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "errors"
    "io"
    "os"
    "encoding/base64"
    "strings"
)

type fileStore struct{}

func getOrCreateLinuxKey() ([]byte, error) {
    keyPath, err := linuxKeyPath()
    if err != nil { return nil, err }
    if b, err := os.ReadFile(keyPath); err == nil && len(b) == 32 {
        return b, nil
    }
    key := make([]byte, 32)
    if _, err := rand.Read(key); err != nil { return nil, err }
    if err := os.WriteFile(keyPath, key, 0o600); err != nil { return nil, err }
    return key, nil
}

func encryptField(key []byte, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil { return nil, err }
    gcm, err := cipher.NewGCM(block)
    if err != nil { return nil, err }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return nil, err }
    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptField(key []byte, ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil { return nil, err }
    gcm, err := cipher.NewGCM(block)
    if err != nil { return nil, err }
    if len(ciphertext) < gcm.NonceSize() { return nil, errors.New("ciphertext scurt") }
    nonce := ciphertext[:gcm.NonceSize()]
    data := ciphertext[gcm.NonceSize():]
    return gcm.Open(nil, nonce, data, nil)
}

func (f *fileStore) Save(rec TokenRecord) error {
    key, err := getOrCreateLinuxKey()
    if err != nil { return err }
    path, err := tokensPath()
    if err != nil { return err }
    // citește existent
    var list []TokenRecord
    if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
        _ = json.Unmarshal(b, &list)
    }
    // criptează refresh_token
    enc, err := encryptField(key, []byte(rec.RefreshToken))
    if err != nil { return err }
    rec.RefreshToken = base64.StdEncoding.EncodeToString(enc)
    // upsert după email
    found := false
    for i := range list {
        if list[i].AccountEmail == rec.AccountEmail {
            list[i] = rec
            found = true
            break
        }
    }
    if !found { list = append(list, rec) }
    b, err := json.MarshalIndent(list, "", "  ")
    if err != nil { return err }
    return os.WriteFile(path, b, 0o600)
}

func (f *fileStore) GetByEmail(email string) (TokenRecord, bool, error) {
    key, err := getOrCreateLinuxKey()
    if err != nil { return TokenRecord{}, false, err }
    path, err := tokensPath()
    if err != nil { return TokenRecord{}, false, err }
    b, err := os.ReadFile(path)
    if err != nil { return TokenRecord{}, false, err }
    var list []TokenRecord
    if err := json.Unmarshal(b, &list); err != nil { return TokenRecord{}, false, err }
    want := strings.TrimSpace(strings.ToLower(email))
    for _, it := range list {
        if strings.TrimSpace(strings.ToLower(it.AccountEmail)) == want {
            ciph, err := base64.StdEncoding.DecodeString(it.RefreshToken)
            if err != nil { return TokenRecord{}, false, err }
            dec, err := decryptField(key, ciph)
            if err != nil { return TokenRecord{}, false, err }
            it.RefreshToken = string(dec)
            return it, true, nil
        }
    }
    return TokenRecord{}, false, nil
}

func (f *fileStore) List() ([]TokenRecord, error) {
    path, err := tokensPath()
    if err != nil { return nil, err }
    b, err := os.ReadFile(path)
    if err != nil { return []TokenRecord{}, nil }
    var list []TokenRecord
    if err := json.Unmarshal(b, &list); err != nil { return nil, err }
    // nu decriptăm aici refresh_token
    return list, nil
}

func New() Store { return &fileStore{} }


