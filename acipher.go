package cipher

import (
  "os"
)



type IACipher interface {
  GetType() string
  
  GetID() ([]byte, error)
  
  GenerateKeyPair() error
  
  PublicKeyToBytes() ([]byte, error)
  BytesToPublicKey(pub []byte) error
  LoadPublicKey(filename string) error
  SavePublicKey(filename string) error
  
  PrivateKeyToBytes(password string) ([]byte, error)
  BytesToPrivateKey(priv []byte, password string) error
  LoadPrivateKey(password string, filename string) error
  SavePrivateKey(password string, filename string) error
  
  PublicKeySerialize() ([]byte, error)
  PublicKeyDeserialize(msg []byte) (error)
    
  Sign(message []byte) ([]byte, error)
  Verify(message []byte, signature []byte) (bool, error)
  
  EncryptWithPublicKey(msg []byte) ([]byte, error)
  DecryptWithPrivateKey(ciphertext []byte) ([]byte, error)
}

type ACipher struct {  
  privateKeyToBytes func(password string) ([]byte, error)
  publicKeyToBytes func() ([]byte, error)
  
  bytesToPrivateKey func(data []byte, password string) error
  bytesToPublicKey  func(data []byte) error
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

func (c *ACipher) LoadPublicKey(filename string) error {
  data, err := os.ReadFile(filename + ".pub")
  if err != nil {
    return err
  }
  return c.bytesToPublicKey(data)
}

func (c *ACipher) SavePublicKey(filename string) error {
  pubfile := filename + ".pub"
  buf, err := c.publicKeyToBytes()
  if err != nil {
    return err
  }
  err = os.WriteFile(pubfile, buf, 0644)
  if err != nil {
    return err
  }
  return nil
}

func (c *ACipher) PublicKeyToBytes() ([]byte, error) { return nil, nil }
func (c *ACipher) BytesToPublicKey(pub []byte) error { return nil }

func (c *ACipher) PrivateKeyToBytes(password string) []byte { return nil }
func (c *ACipher) BytesToPrivateKey(priv []byte, password string) error { return nil }

func (c *ACipher) LoadPrivateKey(password string, filename string) error {
  data, err := os.ReadFile(filename + ".sec")
  if err != nil {
    return err
  }
  return c.bytesToPrivateKey(data, password)
}

func (c *ACipher) SavePrivateKey(password string, filename string) error {
  pubfile := filename + ".sec"
  key, err := c.privateKeyToBytes(password)
  if err != nil {
    return err
  }
  err = os.WriteFile(pubfile, key, 0644)
  if err != nil {
    return err
  }
  return nil
}

