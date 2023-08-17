package cipher

import (
  "os"
)



type IACipher interface {
  GetType() string
  
  GetID() []byte
  
  GenerateKeyPair() bool
  
  PublicKeyToBytes() ([]byte, bool)
  BytesToPublicKey(pub []byte) bool
  LoadPublicKey(filename string) bool
  SavePublicKey(filename string) bool
  
  PrivateKeyToBytes(password string) []byte
  BytesToPrivateKey(priv []byte, password string) bool
  LoadPrivateKey(password string, filename string) bool
  SavePrivateKey(password string, filename string) bool
  
  PublicKeySerialize() ([]byte, bool)
  PublicKeyDeserialize(msg []byte) (bool)
    
  Sign(message []byte) ([]byte, bool)
  Verify(message []byte, signature []byte) (bool)
  
  EncryptWithPublicKey(msg []byte) ([]byte, bool)
  DecryptWithPrivateKey(ciphertext []byte) ([]byte, bool)
}

type ACipher struct {  
  privateKeyToBytes func(password string) []byte
  publicKeyToBytes func() ([]byte, bool)
  
  bytesToPrivateKey func(data []byte, password string) bool
  bytesToPublicKey  func(data []byte) bool
}

func NewACipher(t string) IACipher {
  switch t {
    case "RSA4096":
      c := NewACipherRSA(t)
      return c
    case "P-224":
    case "P-256":
    case "P-384":
    case "P-521":
      c := NewACipherECDSA(t)
      return c
    case "Ed25519":
      c := NewACipherED25519(t)
      return c
    default:
      return nil
  }
  return nil
}

func (c *ACipher) LoadPublicKey(filename string) bool {
  data, err := os.ReadFile(filename + ".pub")
  if err != nil {
    return false
  }
  return c.bytesToPublicKey(data)
}

func (c *ACipher) SavePublicKey(filename string) bool {
  pubfile := filename + ".pub"
  buf, ok := c.publicKeyToBytes()
  if !ok {
    return false
  }
  err := os.WriteFile(pubfile, buf, 0644)
  if err != nil {
    return false
  }
  return true
}

func (c *ACipher) PublicKeyToBytes() ([]byte, bool) { return nil, false }
func (c *ACipher) BytesToPublicKey(pub []byte) bool { return false }

func (c *ACipher) PrivateKeyToBytes(password string) []byte { return nil }
func (c *ACipher) BytesToPrivateKey(priv []byte, password string) bool { return false }

func (c *ACipher) LoadPrivateKey(password string, filename string) bool {
  data, err := os.ReadFile(filename + ".sec")
  if err != nil {
    return false
  }
  return c.bytesToPrivateKey(data, password)
}

func (c *ACipher) SavePrivateKey(password string, filename string) bool {
  pubfile := filename + ".sec"
  err := os.WriteFile(pubfile, c.privateKeyToBytes(password), 0644)
  if err != nil {
    return false
  }
  return true
}

