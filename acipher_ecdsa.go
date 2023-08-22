package cipher

import (
  "errors"
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

func (c *ACipherECDSA) GetID() ([]byte, error) {
  if c.Public == nil {
    return nil, errors.New("Public Key does not exists")
  }
  pubKey := elliptic.Marshal(c.Public, c.Public.X, c.Public.Y)
  sha_512 := sha512.New()
  sha_512.Write([]byte(pubKey))
  return sha_512.Sum(nil), nil
}

func (c *ACipherECDSA) GenerateKeyPair() error {
  params, errp := ECDSAGetParams(c.GetType())
  if errp != nil {
    return errp
  }
  priv, err := ecdsa.GenerateKey(params, rand.Reader)
  if err != nil {
    return err
  }
  c.Private = priv
  if priv != nil {
    public, ok := priv.Public().(*ecdsa.PublicKey)
    if ok {
      c.Public = public
    }
  }
  return nil
}

func (c *ACipherECDSA) PublicKeyToBytes() ([]byte, error) {
  if c.Public == nil {
    return nil, errors.New("Public Key does not exists")
  }
  pubASN1, err := x509.MarshalPKIXPublicKey(c.Public)
  if err != nil {
    return nil, err
  }

  pubBytes := pem.EncodeToMemory(&pem.Block{
    Type:  "ECDSA PUBLIC KEY",
    Bytes: pubASN1,
  })

  return pubBytes, nil
}

// BytesToPublicKey bytes to public key
func (c *ACipherECDSA) BytesToPublicKey(pub []byte) error {
  block, rest := pem.Decode(pub)
  if rest != nil {
    return errors.New("PEM Decode: " + string(rest))
  }
  enc := x509.IsEncryptedPEMBlock(block)
  b := block.Bytes
  if enc {
    var err error
    b, err = x509.DecryptPEMBlock(block, nil)
    if err != nil {
      return err
    }
  }
  ifc, err := x509.ParsePKIXPublicKey(b)
  if err != nil {
    return err
  }
  key, ok := ifc.(*ecdsa.PublicKey)
  if !ok {
    return errors.New("Convert ECDSA Error")
  }
  c.Private = &ecdsa.PrivateKey{}
  if key != nil {
    c.Public = key
  }
  return nil
}


// PrivateKeyToBytes private key to bytes
func (c *ACipherECDSA) PrivateKeyToBytes(password string) ([]byte, error) {
  b, err := x509.MarshalECPrivateKey(c.Private)
  if err != nil {
    return nil, err
  }
  block := &pem.Block{
      Type:  "ECDSA PRIVATE KEY",
      Bytes: b,
    }
  // Encrypt the pem
  if password != "" {
    block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
    if err != nil {
      return nil, err
    }
  }
  return pem.EncodeToMemory(block), nil
}

// BytesToPrivateKey bytes to private key
func (c *ACipherECDSA) BytesToPrivateKey(priv []byte, password string) error {
  block, rest := pem.Decode(priv)
  if rest != nil {
    return errors.New("PEM Decode: " + string(rest))
  }
  enc := x509.IsEncryptedPEMBlock(block)
  b := block.Bytes
  if enc {
    var err error
    b, err = x509.DecryptPEMBlock(block, []byte(password))
    if err != nil {
      return err
    }
  }
  key, err := x509.ParseECPrivateKey(b)
  if err != nil {
    return err
  }
  c.Private = key
  return nil
}

func (c *ACipherECDSA) Sign(message []byte) ([]byte, error) {
  if c.Private == nil {
    return nil, errors.New("Private Key does not exists")
  }
  hashed := sha512.Sum512(message)
  signature, err := ecdsa.SignASN1(rand.Reader, c.Private, hashed[:])
  return signature, err 
}

func (c *ACipherECDSA) Verify(message []byte, signature []byte) (bool, error) {
  if c.Public == nil {
    return false, errors.New("Public Key does not exists")
  }
  hashed := sha512.Sum512(message)
  return ecdsa.VerifyASN1(c.Public, hashed[:], signature), nil
}


// EncryptWithPublicKey encrypts data with public key
func (c *ACipherECDSA) EncryptWithPublicKey(msg []byte) ([]byte, error) {
  return nil, errors.New("This function is not supported")
}

// DecryptWithPrivateKey decrypts data with private key
func (c *ACipherECDSA) DecryptWithPrivateKey(ciphertext []byte) ([]byte, error) {
  return nil, errors.New("This function is not supported")
} 

func (c *ACipherECDSA) PublicKeySerialize() ([]byte, error) {
  return ECDSAPublicKeySerialize(c.Public)
}

func (c *ACipherECDSA) PublicKeyDeserialize(msg []byte) (error) {
  pk, err := ECDSAPublicKeyDeserialize(msg)
  if err != nil {
    return err
  }
  c.Public = pk
  return nil
}

