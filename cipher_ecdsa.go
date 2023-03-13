package cipher

import (
  "crypto/rand"
  "crypto/ecdsa"
	"crypto/elliptic"
  "crypto/x509"
  "encoding/pem"
  "crypto/sha512"
  
  "github.com/golang/glog"
)

type ACipherECDSA struct {
  ACipher
  pkey  *ecdsa.PrivateKey
}

func newACipherECDSA() IACipher {
  var result  = &ACipherECDSA{}
  result.privateKeyToBytes = result.PrivateKeyToBytes
  result.publicKeyToBytes = result.PublicKeyToBytes

  result.bytesToPrivateKey = result.BytesToPrivateKey
  result.bytesToPublicKey = result.BytesToPublicKey
  return result
}

func (c *ACipherECDSA) GetID() []byte {
  pubKey := elliptic.Marshal(c.pkey.PublicKey, c.pkey.PublicKey.X, c.pkey.PublicKey.Y)
  sha_512 := sha512.New()
  sha_512.Write([]byte(pubKey))
  return sha_512.Sum(nil)
}

func (c *ACipherECDSA) GenerateKeyPair() bool {
  var err error
  var priv any
  switch c.GetType() {
    case "P224":
      priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
      break
    case "P256":
      priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
      break
    case "P384":
      priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
      break
    case "P521":
      priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
      break
    default:
      glog.Errorf("ERR: Unrecognized cipher algorithm: %s", c.GetType())
      return false
    }
  if err != nil {
    glog.Errorf("ERR: GenerateKeyPair: %s: %v", c.GetType(), err)
    return false
  }
  c.pkey = priv.(*ecdsa.PrivateKey)
  return true
}

func (c *ACipherECDSA) PublicKeyToBytes() []byte {
  pubASN1, err := x509.MarshalPKIXPublicKey(c.pkey.Public())
  if err != nil {
    glog.Errorf("ERR: CRYPT: MarshalPKIXPublicKey (cipher=%s): %v", c.GetType(), err)
  }

  pubBytes := pem.EncodeToMemory(&pem.Block{
    Type:  "ECDSA PUBLIC KEY",
    Bytes: pubASN1,
  })

  return pubBytes
}

// BytesToPublicKey bytes to public key
func (c *ACipherECDSA) BytesToPublicKey(pub []byte) bool {
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
  key, ok := ifc.(*ecdsa.PublicKey)
  if !ok {
    glog.Errorf("ERR: CRYPT: ParsePKIXPublicKey (cipher=%s): %v", c.GetType(), err)
    return false
  }
  c.pkey = &ecdsa.PrivateKey{}
  c.pkey.PublicKey = (*key)
  return true
}


// PrivateKeyToBytes private key to bytes
func (c *ACipherECDSA) PrivateKeyToBytes(password string) []byte {
  b, err := x509.MarshalPKCS8PrivateKey(&c.pkey)
  if err != nil {
    glog.Errorf("ERR: CRYPT: PrivateKeyToBytes (cipher=%s): %v", c.GetType(), err)
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

func (c *ACipherECDSA) Sign(message []byte) ([]byte, bool) {
  hashed := sha512.Sum512(message)
  signature, err := ecdsa.SignASN1(rand.Reader, c.pkey, hashed[:])
  return signature, err == nil 
}

func (c *ACipherECDSA) Verify(message []byte, signature []byte) (bool) {
  hashed := sha512.Sum512(message)
  return ecdsa.VerifyASN1(c.pkey.Public().(*ecdsa.PublicKey), hashed[:], signature)
}


// EncryptWithPublicKey encrypts data with public key
func (c *ACipherECDSA) EncryptWithPublicKey(msg []byte) ([]byte, bool) {
  /*hash := sha512.New()
  ciphertext, err := ecdsa.EncryptOAEP(hash, rand.Reader,&c.pkey.PublicKey, msg, nil)
  if err != nil {
    glog.Errorf("ERR: CRYPT: EncryptWithPublicKey (cipher=%s): %v", c.GetType(), err)
    return ciphertext, false
  }
  return ciphertext, true
  */
  return nil, false
}

// DecryptWithPrivateKey decrypts data with private key
func (c *ACipherECDSA) DecryptWithPrivateKey(ciphertext []byte) ([]byte, bool) {
  /*hash := sha512.New()
  plaintext, err := ecdsa.DecryptOAEP(hash, rand.Reader, c.pkey, ciphertext, nil)
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
