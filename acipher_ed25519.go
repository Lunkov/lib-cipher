package cipher

import (
  "errors"
  "crypto/rand"
  "crypto/ed25519"
  "crypto/sha512"
  "crypto/x509"
  "encoding/pem"
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

func (c *ACipherED25519) GetID() ([]byte, error) {
  sha_512 := sha512.New()
  sha_512.Write(c.pub)
  return sha_512.Sum(nil), nil
}

func (c *ACipherED25519) GenerateKeyPair() error {
  pub, priv, err := ed25519.GenerateKey(rand.Reader)
  if err != nil {
    return err
  }
  c.pub = pub
  c.pkey = priv
  return nil
}


// BytesToPublicKey bytes to public key
func (c *ACipherED25519) BytesToPublicKey(pub []byte) error {
  block, _ := pem.Decode(pub)
  enc := x509.IsEncryptedPEMBlock(block)
  b := block.Bytes
  var err error
  if enc {
    b, err = x509.DecryptPEMBlock(block, nil)
    if err != nil {
      return err
    }
  }
  ifc, err := x509.ParsePKIXPublicKey(b)
  if err != nil {
    return err
  }
  key, ok := ifc.(*ed25519.PublicKey)
  if !ok {
    return errors.New("Convert ED25519 Error")
  }
  //c.pkey = &ed25519.PrivateKey{}
  c.pub = (*key)
  return nil
}

func (c *ACipherED25519) PublicKeyToBytes() ([]byte, error) {
  pubASN1, err := x509.MarshalPKIXPublicKey(c.pub)
  if err != nil {
    return nil, err
  }

  pubBytes := pem.EncodeToMemory(&pem.Block{
    Type:  "ED25519 PUBLIC KEY",
    Bytes: pubASN1,
  })

  return pubBytes, nil
}

// PrivateKeyToBytes private key to bytes
func (c *ACipherED25519) PrivateKeyToBytes(password string) ([]byte, error) {
  b, err := x509.MarshalPKCS8PrivateKey(&c.pkey)
  if err != nil {
    return nil, err
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
      return nil, err
    }
  }
  return pem.EncodeToMemory(block), nil
}

func (c *ACipherED25519) Sign(message []byte) ([]byte, error) {
  signature := ed25519.Sign(c.pkey, message)
  return signature, nil 
}

func (c *ACipherED25519) Verify(message []byte, signature []byte) (bool, error) {
  return ed25519.Verify(c.pub, message, signature), nil
}

// EncryptWithPublicKey encrypts data with public key
func (c *ACipherED25519) EncryptWithPublicKey(msg []byte) ([]byte, error) {
  /*hash := sha512.New()
  ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader,&c.pkey.PublicKey, msg, nil)
  if err != nil {
    glog.Errorf("ERR: CRYPT: EncryptWithPublicKey (cipher=%s): %v", c.GetType(), err)
    return ciphertext, false
  }
  return ciphertext, true*/
  return nil, errors.New("This function is not supported")
}

// DecryptWithPrivateKey decrypts data with private key
func (c *ACipherED25519) DecryptWithPrivateKey(ciphertext []byte) ([]byte, error) {
  /*hash := sha512.New()
  plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, c.pkey, ciphertext, nil)
  if err != nil {
    glog.Errorf("ERR: CRYPT: DecryptWithPrivateKey (cipher=%s): %v", c.GetType(), err)
    return plaintext, false
  }
  return plaintext, true*/
  return nil, errors.New("This function is not supported")
} 

func (c *ACipherED25519) PublicKeySerialize() ([]byte, error) {
  return nil, errors.New("This function is not supported")
}

func (c *ACipherED25519) PublicKeyDeserialize(msg []byte) (error) {
  return errors.New("This function is not supported")
}
