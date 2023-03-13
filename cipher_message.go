package cipher

import (
  "os"
  
  "github.com/golang/glog"
)

/*
 * SHA-256   32 bytes
 * SHA-512   64 bytes
 * 
 * AES       block size 16 bytes
 * AES 256   key size 64 bytes
 * AES 256   14 rounds for 256-bit keys
 * 
 * AES 128   key size ?? bytes
 * AES 128   10 rounds for 128-bit keys
 */

// https://github.com/lafriks/go-shamir


type IACipher interface {
  SetType(t string)
  GetType() string
  
  GetID() []byte
  
  GenerateKeyPair() bool
  
  PublicKeyToBytes() []byte
  BytesToPublicKey(pub []byte) bool
  LoadPublicKey(filename string) bool
  SavePublicKey(filename string) bool
  
  PrivateKeyToBytes(password string) []byte
  BytesToPrivateKey(priv []byte, password string) bool
  LoadPrivateKey(password string, filename string) bool
  SavePrivateKey(password string, filename string) bool
  
  Sign(message []byte) ([]byte, bool)
  Verify(message []byte, signature []byte) (bool)
  
  EncryptWithPublicKey(msg []byte) ([]byte, bool)
  DecryptWithPrivateKey(ciphertext []byte) ([]byte, bool)
}

type ACipher struct {
  Type    string
  
  privateKeyToBytes func(password string) []byte
  publicKeyToBytes func() []byte
  
  bytesToPrivateKey func(data []byte, password string) bool
  bytesToPublicKey  func(data []byte) bool
}

func NewACipher(t string) IACipher {
  switch t {
    case "RSA4096":
      c := newACipherRSA()
      c.SetType(t)
      return c
    case "P224":
    case "P256":
    case "P384":
    case "P521":
      c := newACipherECDSA()
      c.SetType(t)
      return c
    case "Ed25519":
      c := newACipherED25519()
      c.SetType(t)
      return c
    default:
      glog.Errorf("ERR: Unrecognized cipher algorithm: %s", t)
      return nil
  }
  return nil
}

func (c *ACipher) SetType(t string) { c.Type = t }
func (c *ACipher) GetType() string  { return c.Type }

func (c *ACipher) LoadPublicKey(filename string) bool {
  data, err := os.ReadFile(filename + ".pub")
  if err != nil {
    glog.Errorf("ERR: CRYPT: Load Public Key (file=%s): %v", filename, err)
    return false
  }
  return c.bytesToPublicKey(data)
}

func (c *ACipher) SavePublicKey(filename string) bool {
  pubfile := filename + ".pub"
  err := os.WriteFile(pubfile, c.publicKeyToBytes(), 0644)
  if err != nil {
    glog.Errorf("ERR: CRYPT: Write file (file=%s): %v", pubfile, err)
    return false
  }
  return true
}

func (c *ACipher) PublicKeyToBytes() []byte { return nil }
func (c *ACipher) BytesToPublicKey(pub []byte) bool { return false }

func (c *ACipher) PrivateKeyToBytes(password string) []byte { return nil }
func (c *ACipher) BytesToPrivateKey(priv []byte, password string) bool { return false }

func (c *ACipher) LoadPrivateKey(password string, filename string) bool {
  data, err := os.ReadFile(filename + ".sec")
  if err != nil {
    glog.Errorf("ERR: CRYPT: Load Private Key (file=%s): %v", filename, err)
    return false
  }
  return c.bytesToPrivateKey(data, password)
}

func (c *ACipher) SavePrivateKey(password string, filename string) bool {
  pubfile := filename + ".sec"
  err := os.WriteFile(pubfile, c.privateKeyToBytes(password), 0644)
  if err != nil {
    glog.Errorf("ERR: CRYPT: Write file (file=%s): %v", pubfile, err)
    return false
  }
  return true
}

