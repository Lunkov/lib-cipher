package cipher

import (
)

type TypeCipher struct {
  Code         string
  Name         string
  Description  string
}

type TypesCipher struct {
  mapTypes   map[string]TypeCipher
}

func NewTypesCipher() (*TypesCipher) {
  return &TypesCipher{
      mapTypes  : map[string]TypeCipher{
                                        "RSA4096": TypeCipher{
                                                Code: "RSA4096",
                                                Name: "RSA 4096 bits",
                                                Description: "RSA 4096 bits"},
                                        "P224": TypeCipher{
                                                Code: "P224",
                                                Name: "ECDSA 224",
                                                Description: "ECDSA 224"},
                                        "P256": TypeCipher{
                                                Code: "ECDSA 256",
                                                Name: "ECDSA 256",
                                                Description: "ECDSA 256"},
                                        "P384": TypeCipher{
                                                Code: "P384",
                                                Name: "ECDSA 384",
                                                Description: "ECDSA 384"},
                                        "P521": TypeCipher{
                                                Code: "P521",
                                                Name: "ECDSA 521",
                                                Description: "ECDSA 521"},
                                        "Ed25519": TypeCipher{
                                                Code: "Ed25519",
                                                Name: "Ed25519",
                                                Description: "Ed25519"},
                                      },
  }
}


func (t *TypesCipher) GetCodes() ([]string) {
  keys := make([]string, len(t.mapTypes))

  i := 0
  for _, v := range t.mapTypes {
    keys[i] = v.Name
    i++
  }
  return keys
}

func (t *TypesCipher) FindCodeByName(code string) (string, bool) {
  for k, v := range t.mapTypes {
    if code == v.Name {
      return k, true
    }
  }
  return "", false
}

func (t *TypesCipher) GetName(code string) (string) {
  l, ok := t.mapTypes[code]
  if ok {
    return l.Name
  }
  return ""
}

func (t *TypesCipher) Get(code string) (*TypeCipher) {
  l, ok := t.mapTypes[code]
  if ok {
    return &l
  }
  return nil
}
