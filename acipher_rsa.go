package cipher

import (
  "crypto"
  "crypto/rand"
  "crypto/rsa"
  
  "crypto/sha512"
  "crypto/x509"
  "encoding/pem"
)

type ACipherRSA struct {
  ACipher

  Type    string
  pkey   *rsa.PrivateKey
}

func NewACipherRSA(t string) IACipher {
  var result  = &ACipherRSA{}
  result.Type = t
  result.privateKeyToBytes = result.PrivateKeyToBytes
  result.publicKeyToBytes = result.PublicKeyToBytes

  result.bytesToPrivateKey = result.BytesToPrivateKey
  result.bytesToPublicKey = result.BytesToPublicKey
  return result
}

func (c *ACipherRSA) GetType() string  { return c.Type }

func (c *ACipherRSA) GenerateKeyPair() bool {
  var err error
  var priv any
  switch c.GetType() {
    case "RSA4096":
      priv, err = rsa.GenerateKey(rand.Reader, 4096)
      break
    default:
      return false
    }
  if err != nil {
    return false
  }
  c.pkey = priv.(*rsa.PrivateKey)
  return true
}

func (c *ACipherRSA) GetID() []byte {
  // TODO https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md
  pubASN1, err := x509.MarshalPKIXPublicKey(c.pkey.Public())
	if err != nil {
		return nil
	}
  sha_512 := sha512.New()
  sha_512.Write(pubASN1)
  return sha_512.Sum(nil)
}

func (c *ACipherRSA) PublicKeyToBytes() ([]byte, bool) {
  pubASN1, err := x509.MarshalPKIXPublicKey(c.pkey.Public())
  if err != nil {
    return nil, false
  }

  pubBytes := pem.EncodeToMemory(&pem.Block{
    Type:  "RSA PUBLIC KEY",
    Bytes: pubASN1,
  })

  return pubBytes, true
}

// BytesToPublicKey bytes to public key
func (c *ACipherRSA) BytesToPublicKey(pub []byte) bool {
  block, _ := pem.Decode(pub)
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
  key, ok := ifc.(*rsa.PublicKey)
  if !ok {
    return false
  }
  c.pkey = &rsa.PrivateKey{}
  c.pkey.PublicKey = (*key)
  return true
}

// PrivateKeyToBytes private key to bytes
func (c *ACipherRSA) PrivateKeyToBytes(password string) []byte {
  block := &pem.Block{
      Type:  "RSA PRIVATE KEY",
      Bytes: x509.MarshalPKCS1PrivateKey(c.pkey),
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
func (c *ACipherRSA) BytesToPrivateKey(priv []byte, password string) bool {
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
  key, err := x509.ParsePKCS1PrivateKey(b)
  if err != nil {
    return false
  }
  c.pkey = key
  return true
}

func (c *ACipherRSA) Sign(message []byte) ([]byte, bool) {
  if c.pkey == nil {
    return nil, false
  }
  
  hashed := sha512.Sum512(message)

  signature, err := rsa.SignPKCS1v15(rand.Reader, c.pkey, crypto.SHA512, hashed[:])
  if err != nil {
    return signature, false
  }

  return signature, true 
}

func (c *ACipherRSA) Verify(message []byte, signature []byte) (bool) {
  if c.pkey == nil {
    return false
  }

  hashed := sha512.Sum512(message)

  err := rsa.VerifyPKCS1v15(&c.pkey.PublicKey, crypto.SHA512, hashed[:], signature)
  if err != nil {
    return false
  }

  return true
}

// EncryptWithPublicKey encrypts data with public key
func (c *ACipherRSA) EncryptWithPublicKey(msg []byte) ([]byte, bool) {
  if c.pkey == nil {
    return nil, false
  }
  return RSAEncryptWithPublicKey(&c.pkey.PublicKey, msg)
}

func (c *ACipherRSA) DecryptWithPrivateKey(msg []byte) ([]byte, bool) {
  if c.pkey == nil {
    return nil, false
  }
  return RSADecryptWithPrivateKey(c.pkey, msg)
}

func (c *ACipherRSA) PublicKeySerialize() ([]byte, bool) {
  return nil, false
}

func (c *ACipherRSA) PublicKeyDeserialize(msg []byte) (bool) {
  return false
}
