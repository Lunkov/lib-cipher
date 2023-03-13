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
  pub   ed25519.PublicKey
  pkey  ed25519.PrivateKey
}

func newACipherED25519() IACipher {
  var result  = &ACipherED25519{}
  result.privateKeyToBytes = result.PrivateKeyToBytes
  result.publicKeyToBytes = result.PublicKeyToBytes

  result.bytesToPrivateKey = result.BytesToPrivateKey
  result.bytesToPublicKey = result.BytesToPublicKey
  return result
}

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


/*
func (c *CipherMessage) GenerateKeyPairAndSave(RSABits int, password string, filename string) bool {
  privkey, err := rsa.GenerateKey(rand.Reader, RSABits)
  if err != nil {
    glog.Errorf("ERR: CRYPT: GenerateKey (cipher=%s): %v", DefaultCipher, err)
    return false
  }
  c.rsaPrivateKey = privkey
  
  err = os.WriteFile(filename, c.PrivateKeyToBytes(password), 0600)
  if err != nil {
    glog.Errorf("ERR: CRYPT: Write file (file=%s): %v", filename, err)
    return false
  }
  
  pubfile := filename + ".pub"
  err = os.WriteFile(pubfile, c.PublicKeyToBytes(), 0644)
  if err != nil {
    glog.Errorf("ERR: CRYPT: Write file (file=%s): %v", pubfile, err)
    return false
  }
  return true
}

func (c *CipherMessage) GenerateRSAKeyPair(RSABits int) (*rsa.PrivateKey, bool) {
  privkey, err := rsa.GenerateKey(rand.Reader, RSABits)
  if err != nil {
    glog.Errorf("ERR: CRYPT: GenerateKey (cipher=%s): %v", DefaultCipher, err)
    return nil, false
  }
  c.rsaPrivateKey = privkey
  
  return privkey, true
}

func (c *CipherMessage) GenerateKeyPair(RSABits int, password string) ([]byte, []byte, bool) {
  privkey, err := rsa.GenerateKey(rand.Reader, RSABits)
  if err != nil {
    glog.Errorf("ERR: CRYPT: GenerateKey (cipher=%s): %v", DefaultCipher, err)
    return nil, nil, false
  }
  c.rsaPrivateKey = privkey
  
  return c.PublicKeyToBytes(), c.PrivateKeyToBytes(password), true
}

// PrivateKeyToBytes private key to bytes
func (c *CipherMessage) PrivateKeyToBytes(password string) []byte {
  block := &pem.Block{
      Type:  "RSA PRIVATE KEY",
      Bytes: x509.MarshalPKCS1PrivateKey(c.rsaPrivateKey),
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

// PublicKeyToBytes public key to bytes
func (c *CipherMessage) PublicKeyToBytes() []byte {
  pubASN1, err := x509.MarshalPKIXPublicKey(c.rsaPrivateKey.Public())
  if err != nil {
    glog.Errorf("ERR: CRYPT: MarshalPKIXPublicKey (cipher=%s): %v", DefaultCipher, err)
  }

  pubBytes := pem.EncodeToMemory(&pem.Block{
    Type:  "RSA PUBLIC KEY",
    Bytes: pubASN1,
  })

  return pubBytes
}

func (c *CipherMessage) Sign(message []byte) ([]byte, bool) {
  rng := rand.Reader

  // Only small messages can be signed directly; thus the hash of a
  // message, rather than the message itself, is signed. This requires
  // that the hash function be collision resistant. SHA-256 is the
  // least-strong hash function that should be used for this at the time
  // of writing (2016).
  hashed := sha512.Sum512(message)

  signature, err := rsa.SignPKCS1v15(rng, c.rsaPrivateKey, crypto.SHA512, hashed[:])
  if err != nil {
    glog.Errorf("ERR: CRYPT: Signing: %s", err)
    return signature, false
  }

  return signature, true 
}

func (c *CipherMessage) Verify(message []byte, signature []byte) (bool) {
  hashed := sha512.Sum512(message)

  err := rsa.VerifyPKCS1v15(&c.rsaPrivateKey.PublicKey, crypto.SHA512, hashed[:], signature)
  if err != nil {
    glog.Errorf("ERR: CRYPT: Verification: %s", err)
    return false
  }

  return true
}

func (c *CipherMessage) LoadPrivateKey(password string, filename string) bool {
  data, err := os.ReadFile(filename)
  if err != nil {
    glog.Errorf("ERR: CRYPT: Load Private Key (file=%s): %v", filename, err)
    return false
  }
  return c.BytesToPrivateKey(data, password)
}

// BytesToPrivateKey bytes to private key
func (c *CipherMessage) BytesToPrivateKey(priv []byte, password string) bool {
  block, _ := pem.Decode(priv)
  enc := x509.IsEncryptedPEMBlock(block)
  b := block.Bytes
  var err error
  if enc {
    b, err = x509.DecryptPEMBlock(block, []byte(password))
    if err != nil {
      glog.Errorf("ERR: CRYPT: Encrypt (cipher=%s): %v", DefaultCipher, err)
      return false
    }
  }
  key, err := x509.ParsePKCS1PrivateKey(b)
  if err != nil {
    glog.Errorf("ERR: CRYPT: ParsePKCS1PrivateKey (cipher=%s): %v", DefaultCipher, err)
    return false
  }
  c.rsaPrivateKey = key
  return true
}

func (c *CipherMessage) LoadPublicKey(filename string) bool {
  data, err := os.ReadFile(filename)
  if err != nil {
    glog.Errorf("ERR: CRYPT: Load Public Key (file=%s): %v", filename, err)
    return false
  }
  return c.BytesToPublicKey(data)
}

// BytesToPublicKey bytes to public key
func (c *CipherMessage) BytesToPublicKey(pub []byte) bool {
  block, _ := pem.Decode(pub)
  enc := x509.IsEncryptedPEMBlock(block)
  b := block.Bytes
  var err error
  if enc {
    b, err = x509.DecryptPEMBlock(block, nil)
    if err != nil {
      glog.Errorf("ERR: CRYPT: DecryptPEMBlock (cipher=%s): %v", DefaultCipher, err)
      return false
    }
  }
  ifc, err := x509.ParsePKIXPublicKey(b)
  if err != nil {
    glog.Errorf("ERR: CRYPT: ParsePKIXPublicKey (cipher=%s): %v", DefaultCipher, err)
    return false
  }
  key, ok := ifc.(*rsa.PublicKey)
  if !ok {
    glog.Errorf("ERR: CRYPT: ParsePKIXPublicKey (cipher=%s): %v", DefaultCipher, err)
    return false
  }
  c.rsaPrivateKey = &rsa.PrivateKey{}
  c.rsaPrivateKey.PublicKey = (*key)
  return true
}


// EncryptWithPublicKey encrypts data with public key
func (c *CipherMessage) EncryptWithPublicKey(msg []byte) ([]byte, bool) {
  hash := sha512.New()
  ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader,&c.rsaPrivateKey.PublicKey, msg, nil)
  if err != nil {
    glog.Errorf("ERR: CRYPT: EncryptWithPublicKey (cipher=%s): %v", DefaultCipher, err)
    return ciphertext, false
  }
  return ciphertext, true
}

// DecryptWithPrivateKey decrypts data with private key
func (c *CipherMessage) DecryptWithPrivateKey(ciphertext []byte) ([]byte, bool) {
  hash := sha512.New()
  plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, c.rsaPrivateKey, ciphertext, nil)
  if err != nil {
    glog.Errorf("ERR: CRYPT: DecryptWithPrivateKey (cipher=%s): %v", DefaultCipher, err)
    return plaintext, false
  }
  return plaintext, true
} 

// encrypt string to base64 crypto using AES
func (c *CipherMessage) AESEncrypt(key []byte, plaintext []byte) ([]byte, bool) {
  block, err := aes.NewCipher(key)
  if err != nil {
    glog.Errorf("ERR: CRYPT: AESEncrypt (cipher=%s): %v", DefaultCipher, err)
    return plaintext, false
  }

  // The IV needs to be unique, but not secure. Therefore it's common to
  // include it at the beginning of the ciphertext.
  ciphertext := make([]byte, aes.BlockSize+len(plaintext))
  iv := ciphertext[:aes.BlockSize]
  if _, err := io.ReadFull(rand.Reader, iv); err != nil {
    glog.Errorf("ERR: CRYPT: AESEncrypt (ReadFull): %v", err)
    return plaintext, false
  }

  stream := cipher.NewCFBEncrypter(block, iv)
  stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

  return ciphertext, true
}

// decrypt from base64 to decrypted string
func (c *CipherMessage) AESDecrypt(key []byte, ciphertext []byte) ([]byte, bool) {
  block, err := aes.NewCipher(key)
  if err != nil {
    glog.Errorf("ERR: CRYPT: AESDecrypt (NewCipher): %v", err)
    return ciphertext, false
  }

  // The IV needs to be unique, but not secure. Therefore it's common to
  // include it at the beginning of the ciphertext.
  if len(ciphertext) < aes.BlockSize {
    glog.Errorf("ERR: CRYPT: AESDecrypt (BlockSize): %v", err)
    return ciphertext, false
  }
  iv := ciphertext[:aes.BlockSize]
  ciphertext = ciphertext[aes.BlockSize:]
  stream := cipher.NewCFBDecrypter(block, iv)

  // XORKeyStream can work in-place if the two arguments are the same.
  stream.XORKeyStream(ciphertext, ciphertext)
  return ciphertext, true
}

func (c *CipherMessage) SHA512(key []byte) ([]byte, bool) {
  sha_512 := sha512.New()
  sha_512.Write(key)
  return sha_512.Sum(nil), true
}

func (c *CipherMessage) SHA256(key []byte) ([]byte, bool) {
  sha_256 := sha256.New()
  sha_256.Write(key)
  return sha_256.Sum(nil), true
}
*/
