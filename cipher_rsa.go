package cipher

import (
  "crypto"
  "crypto/rand"
  "crypto/rsa"
  
  "crypto/sha512"
  "crypto/x509"
  "encoding/pem"
  
  "github.com/golang/glog"
)

type ACipherRSA struct {
  ACipher
  pkey  *rsa.PrivateKey
}

func newACipherRSA() IACipher {
  var result  = &ACipherRSA{}
  result.privateKeyToBytes = result.PrivateKeyToBytes
  result.publicKeyToBytes = result.PublicKeyToBytes

  result.bytesToPrivateKey = result.BytesToPrivateKey
  result.bytesToPublicKey = result.BytesToPublicKey
  return result
}


func (c *ACipherRSA) GenerateKeyPair() bool {
  var err error
  var priv any
  switch c.GetType() {
    case "RSA4096":
      priv, err = rsa.GenerateKey(rand.Reader, 4096)
      break
    default:
      glog.Errorf("ERR: Unrecognized cipher algorithm: %s", c.GetType())
      return false
    }
  if err != nil {
    glog.Errorf("ERR: GenerateKeyPair: %s: %v", c.GetType(), err)
    return false
  }
  c.pkey = priv.(*rsa.PrivateKey)
  return true
}

func (c *ACipherRSA) GetID() []byte {
  pubASN1, err := x509.MarshalPKIXPublicKey(c.pkey.Public())
	if err != nil {
		glog.Errorf("ERR: MarshalPKIXPublicKey: %v", err)
    return nil
	}
  sha_512 := sha512.New()
  sha_512.Write(pubASN1)
  return sha_512.Sum(nil)
}

func (c *ACipherRSA) PublicKeyToBytes() []byte {
  pubASN1, err := x509.MarshalPKIXPublicKey(c.pkey.Public())
  if err != nil {
    glog.Errorf("ERR: CRYPT: MarshalPKIXPublicKey (cipher=%s): %v", c.GetType(), err)
  }

  pubBytes := pem.EncodeToMemory(&pem.Block{
    Type:  "RSA PUBLIC KEY",
    Bytes: pubASN1,
  })

  return pubBytes
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
      glog.Errorf("ERR: CRYPT: DecryptPEMBlock (cipher=%s): %v", c.GetType(), err)
      return false
    }
  }
  ifc, err := x509.ParsePKIXPublicKey(b)
  if err != nil {
    glog.Errorf("ERR: CRYPT: ParsePKIXPublicKey (cipher=%s): %v", c.GetType(), err)
    return false
  }
  key, ok := ifc.(*rsa.PublicKey)
  if !ok {
    glog.Errorf("ERR: CRYPT: ParsePKIXPublicKey (cipher=%s): %v", c.GetType(), err)
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
      glog.Errorf("ERR: CRYPT: Encrypt (cipher=%s): %v", c.GetType(), err)
      return false
    }
  }
  key, err := x509.ParsePKCS1PrivateKey(b)
  if err != nil {
    glog.Errorf("ERR: CRYPT: ParsePKCS1PrivateKey (cipher=%s): %v", c.GetType(), err)
    return false
  }
  c.pkey = key
  return true
}

func (c *ACipherRSA) Sign(message []byte) ([]byte, bool) {
  rng := rand.Reader

  // Only small messages can be signed directly; thus the hash of a
  // message, rather than the message itself, is signed. This requires
  // that the hash function be collision resistant. SHA-256 is the
  // least-strong hash function that should be used for this at the time
  // of writing (2016).
  hashed := sha512.Sum512(message)

  signature, err := rsa.SignPKCS1v15(rng, c.pkey, crypto.SHA512, hashed[:])
  if err != nil {
    glog.Errorf("ERR: CRYPT: Signing: %s", err)
    return signature, false
  }

  return signature, true 
}

func (c *ACipherRSA) Verify(message []byte, signature []byte) (bool) {
  hashed := sha512.Sum512(message)

  err := rsa.VerifyPKCS1v15(&c.pkey.PublicKey, crypto.SHA512, hashed[:], signature)
  if err != nil {
    glog.Errorf("ERR: CRYPT: Verification: %s", err)
    return false
  }

  return true
}


// EncryptWithPublicKey encrypts data with public key
func (c *ACipherRSA) EncryptWithPublicKey(msg []byte) ([]byte, bool) {
  hash := sha512.New()
  ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader,&c.pkey.PublicKey, msg, nil)
  if err != nil {
    glog.Errorf("ERR: CRYPT: EncryptWithPublicKey (cipher=%s): %v", c.GetType(), err)
    return ciphertext, false
  }
  return ciphertext, true
}

// DecryptWithPrivateKey decrypts data with private key
func (c *ACipherRSA) DecryptWithPrivateKey(ciphertext []byte) ([]byte, bool) {
  hash := sha512.New()
  plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, c.pkey, ciphertext, nil)
  if err != nil {
    glog.Errorf("ERR: CRYPT: DecryptWithPrivateKey (cipher=%s): %v", c.GetType(), err)
    return plaintext, false
  }
  return plaintext, true
} 
