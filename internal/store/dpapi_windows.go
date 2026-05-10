//go:build windows

package store

import (
    "encoding/json"
    "os"
    "syscall"
    "unsafe"
    "encoding/base64"
    "strings"
)

// Minimal DPAPI (CryptProtectData / CryptUnprotectData)
type dataBlob struct {
    cbData uint32
    pbData *byte
}

var (
    crypt32            = syscall.NewLazyDLL("Crypt32.dll")
    procProtectData    = crypt32.NewProc("CryptProtectData")
    procUnprotectData  = crypt32.NewProc("CryptUnprotectData")
    kernel32           = syscall.NewLazyDLL("Kernel32.dll")
    procLocalFree      = kernel32.NewProc("LocalFree")
)

func bytesToBlob(b []byte) dataBlob {
    if len(b) == 0 { return dataBlob{} }
    return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

func blobToBytes(blob dataBlob) []byte {
    if blob.cbData == 0 { return nil }
    b := make([]byte, blob.cbData)
    copy(b, unsafe.Slice(blob.pbData, blob.cbData))
    return b
}

func cryptProtect(data []byte) ([]byte, error) {
    in := bytesToBlob(data)
    var out dataBlob
    r1, _, e1 := procProtectData.Call(
        uintptr(unsafe.Pointer(&in)),
        0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&out)))
    if r1 == 0 { return nil, e1 }
    defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
    return blobToBytes(out), nil
}

func cryptUnprotect(data []byte) ([]byte, error) {
    in := bytesToBlob(data)
    var out dataBlob
    r1, _, e1 := procUnprotectData.Call(
        uintptr(unsafe.Pointer(&in)),
        0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&out)))
    if r1 == 0 { return nil, e1 }
    defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
    return blobToBytes(out), nil
}

type fileStore struct{}

func (f *fileStore) Save(rec TokenRecord) error {
    path, err := tokensPath()
    if err != nil { return err }
    var list []TokenRecord
    if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
        _ = json.Unmarshal(b, &list)
    }
    if rec.RefreshToken != "" {
        enc, err := cryptProtect([]byte(rec.RefreshToken))
        if err != nil { return err }
        rec.RefreshToken = base64.StdEncoding.EncodeToString(enc)
    }
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
    path, err := tokensPath()
    if err != nil { return TokenRecord{}, false, err }
    b, err := os.ReadFile(path)
    if err != nil { return TokenRecord{}, false, err }
    var list []TokenRecord
    if err := json.Unmarshal(b, &list); err != nil { return TokenRecord{}, false, err }
    want := strings.TrimSpace(strings.ToLower(email))
    for _, it := range list {
        if strings.TrimSpace(strings.ToLower(it.AccountEmail)) == want {
            if it.RefreshToken != "" {
                ciph, err := base64.StdEncoding.DecodeString(it.RefreshToken)
                if err != nil { return TokenRecord{}, false, err }
                dec, err := cryptUnprotect(ciph)
                if err != nil { return TokenRecord{}, false, err }
                it.RefreshToken = string(dec)
            }
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
    return list, nil
}

func New() Store { return &fileStore{} }


