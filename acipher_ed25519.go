package cipher

import (
  "crypto/rand"
  "crypto/ed25519"
  "crypto/sha512"
  "crypto/x509"
  "encoding/pem"
  
  "github.com/golang/glog"
)

type ACipherED25519 struct {
  ACipher

  Type    string
  pub     ed25519.PublicKey
  pkey    ed25519.PrivateKey
}

func NewACipherED25519(t string) IACipher {
  var result  = &ACipherED25519{}
  result.Type = t
  result.privateKeyToBytes = result.PrivateKeyToBytes
  result.publicKeyToBytes = result.PublicKeyToBytes

  result.bytesToPrivateKey = result.BytesToPrivateKey
  result.bytesToPublicKey = result.BytesToPublicKey
  return result
}

func (c *ACipherED25519) GetType() string  { return c.Type }

func (c *ACipherED25519) GetID() []byte {
  sha_512 := sha512.New()
  sha_512.Write(c.pub)
  return sha_512.Sum(nil)
}

func (c *ACipherED25519) GenerateKeyPair() bool {
  pub, priv, err := ed25519.GenerateKey(rand.Reader)
  if err != nil {
    glog.Errorf("ERR: GenerateKeyPair: %s: %v", c.GetType(), err)
    return false
  }
  c.pub = pub
  c.pkey = priv
  return true
}


// BytesToPublicKey bytes to public key
func (c *ACipherED25519) BytesToPublicKey(pub []byte) bool {
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
  key, ok := ifc.(*ed25519.PublicKey)
  if !ok {
    glog.Errorf("ERR: CRYPT: ParsePKIXPublicKey (cipher=%s): %v", c.GetType(), err)
    return false
  }
  //c.pkey = &ed25519.PrivateKey{}
  c.pub = (*key)
  return true
}

func (c *ACipherED25519) PublicKeyToBytes() []byte {
  pubASN1, err := x509.MarshalPKIXPublicKey(c.pub)
  if err != nil {
    glog.Errorf("ERR: CRYPT: MarshalPKIXPublicKey (cipher=%s): %v", c.GetType(), err)
  }

  pubBytes := pem.EncodeToMemory(&pem.Block{
    Type:  "ED25519 PUBLIC KEY",
    Bytes: pubASN1,
  })

  return pubBytes
}

// PrivateKeyToBytes private key to bytes
func (c *ACipherED25519) PrivateKeyToBytes(password string) []byte {
  b, err := x509.MarshalPKCS8PrivateKey(&c.pkey)
  if err != nil {
    glog.Errorf("ERR: CRYPT: PrivateKeyToBytes (cipher=%s): %v", c.GetType(), err)
    return nil
  }
  block := &pem.Block{
      Type:  "ED25519 PRIVATE KEY",
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

func (c *ACipherED25519) Sign(message []byte) ([]byte, bool) {
  signature := ed25519.Sign(c.pkey, message)
  return signature, true 
}

func (c *ACipherED25519) Verify(message []byte, signature []byte) (bool) {
  return ed25519.Verify(c.pub, message, signature)
}

// EncryptWithPublicKey encrypts data with public key
func (c *ACipherED25519) EncryptWithPublicKey(msg []byte) ([]byte, bool) {
  /*hash := sha512.New()
  ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader,&c.pkey.PublicKey, msg, nil)
  if err != nil {
    glog.Errorf("ERR: CRYPT: EncryptWithPublicKey (cipher=%s): %v", c.GetType(), err)
    return ciphertext, false
  }
  return ciphertext, true*/
  return nil, false
}

// DecryptWithPrivateKey decrypts data with private key
func (c *ACipherED25519) DecryptWithPrivateKey(ciphertext []byte) ([]byte, bool) {
  /*hash := sha512.New()
  plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, c.pkey, ciphertext, nil)
  if err != nil {
    glog.Errorf("ERR: CRYPT: DecryptWithPrivateKey (cipher=%s): %v", c.GetType(), err)
    return plaintext, false
  }
  return plaintext, true*/
  return nil, false
} 

func (c *ACipherED25519) PublicKeySerialize() ([]byte, bool) {
  return nil, false
}

func (c *ACipherED25519) PublicKeyDeserialize(msg []byte) (bool) {
  return false
}
