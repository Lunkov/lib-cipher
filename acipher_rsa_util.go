package cipher

import (
  "errors"
  "crypto/rand"
  "crypto/rsa"
  
  "crypto/sha512"
)

// EncryptWithPublicKey encrypts data with public key
func RSAEncryptWithPublicKey(pk *rsa.PublicKey, msg []byte) ([]byte, error) {
  if pk == nil {
    return nil, errors.New("Public Key does not exists")
  }
  hash := sha512.New()
  msgLen := len(msg)
  step := pk.Size() - 2*hash.Size() - 2
  var encryptedBytes []byte

  for start := 0; start < msgLen; start += step {
    finish := start + step
    if finish > msgLen {
      finish = msgLen
    }

    encryptedBlockBytes, err := rsa.EncryptOAEP(hash, rand.Reader, pk, msg[start:finish], nil)
    if err != nil {
      return nil, err
    }

    encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
  }

  return encryptedBytes, nil
}

// DecryptWithPrivateKey decrypts data with private key
func RSADecryptWithPrivateKey(privkey *rsa.PrivateKey, msg []byte) ([]byte, error) {
  if privkey == nil {
    return nil, errors.New("Private Key does not exists")
  }
  hash := sha512.New()

  msgLen := len(msg)
  step := privkey.PublicKey.Size()
  var decryptedBytes []byte

  for start := 0; start < msgLen; start += step {
    finish := start + step
    if finish > msgLen {
      finish = msgLen
    }

    decryptedBlockBytes, err := rsa.DecryptOAEP(hash, rand.Reader, privkey, msg[start:finish], nil)
    if err != nil {
      return nil, err
    }

    decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
  }

  return decryptedBytes, nil
}

