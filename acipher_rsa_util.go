package cipher

import (
  "crypto/rand"
  "crypto/rsa"
  
  "crypto/sha512"
)

// EncryptWithPublicKey encrypts data with public key
func RSAEncryptWithPublicKey(pk *rsa.PublicKey, msg []byte) ([]byte, bool) {
  if pk == nil {
    return nil, false
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
      return nil, false
    }

    encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
  }

  return encryptedBytes, true
}

// DecryptWithPrivateKey decrypts data with private key
func RSADecryptWithPrivateKey(privkey *rsa.PrivateKey, msg []byte) ([]byte, bool) {
  if privkey == nil {
    return nil, false
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
      return nil, false
    }

    decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
  }

  return decryptedBytes, true
}

