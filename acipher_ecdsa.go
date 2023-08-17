package cipher

import (
  "crypto/rand"
  "crypto/ecdsa"
	"crypto/elliptic"
  "crypto/x509"
  "encoding/pem"
  "crypto/sha512"
)

type ACipherECDSA struct {
  ACipher

  Type            string
  
  Private        *ecdsa.PrivateKey
	Public         *ecdsa.PublicKey
}

func NewACipherECDSA(t string) IACipher {
  var result  = &ACipherECDSA{}
  result.Type = t
  
  result.privateKeyToBytes = result.PrivateKeyToBytes
  result.publicKeyToBytes = result.PublicKeyToBytes

  result.bytesToPrivateKey = result.BytesToPrivateKey
  result.bytesToPublicKey = result.BytesToPublicKey
  
  return result
}

func (c *ACipherECDSA) GetType() string  { return c.Type }

func (c *ACipherECDSA) GetID() []byte {
  if c.Public == nil {
    return nil
  }
  pubKey := elliptic.Marshal(c.Public, c.Public.X, c.Public.Y)
  sha_512 := sha512.New()
  sha_512.Write([]byte(pubKey))
  return sha_512.Sum(nil)
}

func (c *ACipherECDSA) GenerateKeyPair() bool {
  params, ok := ECDSAGetParams(c.GetType())
  if !ok {
    return false
  }
  priv, err := ecdsa.GenerateKey(params, rand.Reader)
  if err != nil {
    return false
  }
  c.Private = priv
  if priv != nil {
    public, ok := priv.Public().(*ecdsa.PublicKey)
    if ok {
      c.Public = public
    }
  }
  return true
}

func (c *ACipherECDSA) PublicKeyToBytes() ([]byte, bool) {
  if c.Public == nil {
    return nil, false
  }
  pubASN1, err := x509.MarshalPKIXPublicKey(c.Public)
  if err != nil {
    return nil, false
  }

  pubBytes := pem.EncodeToMemory(&pem.Block{
    Type:  "ECDSA PUBLIC KEY",
    Bytes: pubASN1,
  })

  return pubBytes, true
}

// BytesToPublicKey bytes to public key
func (c *ACipherECDSA) BytesToPublicKey(pub []byte) bool {
  block, _ := pem.Decode(pub)
  if block == nil {
    return false
  }
  enc := x509.IsEncryptedPEMBlock(block)
  b := block.Bytes
  var err error
  if enc {
    b, err = x509.DecryptPEMBlock(block, nil)
    if err != nil {
      return false
    }
  }
  ifc, err := x509.ParsePKIXPublicKey(b)
  if err != nil {
    return false
  }
  key, ok := ifc.(*ecdsa.PublicKey)
  if !ok {
    return false
  }
  c.Private = &ecdsa.PrivateKey{}
  if key != nil {
    c.Public = key
  }
  return true
}


// PrivateKeyToBytes private key to bytes
func (c *ACipherECDSA) PrivateKeyToBytes(password string) []byte {
  b, err := x509.MarshalECPrivateKey(c.Private)
  if err != nil {
    return nil
  }
  block := &pem.Block{
      Type:  "ECDSA PRIVATE KEY",
      Bytes: b,
    }
  // Encrypt the pem
  if password != "" {
    var err error
    block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
    if err != nil {
      return nil
    }
  }
  return pem.EncodeToMemory(block)
}

// BytesToPrivateKey bytes to private key
func (c *ACipherECDSA) BytesToPrivateKey(priv []byte, password string) bool {
  block, _ := pem.Decode(priv)
  enc := x509.IsEncryptedPEMBlock(block)
  b := block.Bytes
  var err error
  if enc {
    b, err = x509.DecryptPEMBlock(block, []byte(password))
    if err != nil {
      return false
    }
  }
  key, err := x509.ParseECPrivateKey(b)
  if err != nil {
    return false
  }
  c.Private = key
  return true
}

func (c *ACipherECDSA) Sign(message []byte) ([]byte, bool) {
  if c.Private == nil {
    return nil, false
  }
  hashed := sha512.Sum512(message)
  signature, err := ecdsa.SignASN1(rand.Reader, c.Private, hashed[:])
  return signature, err == nil 
}

func (c *ACipherECDSA) Verify(message []byte, signature []byte) (bool) {
  if c.Public == nil {
    return false
  }
  hashed := sha512.Sum512(message)
  return ecdsa.VerifyASN1(c.Public, hashed[:], signature)
}


// EncryptWithPublicKey encrypts data with public key
func (c *ACipherECDSA) EncryptWithPublicKey(msg []byte) ([]byte, bool) {
  return nil, false
}

// DecryptWithPrivateKey decrypts data with private key
func (c *ACipherECDSA) DecryptWithPrivateKey(ciphertext []byte) ([]byte, bool) {
  return nil, false
} 

func (c *ACipherECDSA) PublicKeySerialize() ([]byte, bool) {
  return ECDSAPublicKeySerialize(c.Public)
}

func (c *ACipherECDSA) PublicKeyDeserialize(msg []byte) (bool) {
  pk, ok := ECDSAPublicKeyDeserialize(msg)
  if ok {
    c.Public = pk
  }
  return ok
}

