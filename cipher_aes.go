package cipher

import (
  "errors"
  "io"
  "crypto/rand"
  "crypto/aes"
  "crypto/sha256"
  "crypto/sha512"
  "crypto/cipher"
  "golang.org/x/crypto/scrypt"
)


/*
 * SHA-256   32 bytes
 * SHA-512   64 bytes
 * 
 * AES       block size 16 bytes
 * AES 256   key size 64 bytes
 * AES 256   14 rounds for 256-bit keys
 * 
 * AES 128   key size ?? bytes
 * AES 128   10 rounds for 128-bit keys
 */

// https://github.com/lafriks/go-shamir

type SCipher struct {
  //Type    string
}

func NewSCipher() *SCipher {
  return &SCipher{}
}

func (c *SCipher) AESCreateKey() ([]byte, error) {
  key := make([]byte, 64)
  _, err := rand.Read(key)
  if err != nil {
    return nil, err
  }
  return key, nil
}

// encrypt string to base64 crypto using AES
func (c *SCipher) AESEncrypt(key []byte, plaintext []byte) ([]byte, error) {
  block, err := aes.NewCipher(key)
  if err != nil {
    return plaintext, err
  }

  // The IV needs to be unique, but not secure. Therefore it's common to
  // include it at the beginning of the ciphertext.
  ciphertext := make([]byte, aes.BlockSize+len(plaintext))
  iv := ciphertext[:aes.BlockSize]
  if _, err := io.ReadFull(rand.Reader, iv); err != nil {
    return plaintext, err
  }

  stream := cipher.NewCFBEncrypter(block, iv)
  stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

  return ciphertext, nil
}

// decrypt from base64 to decrypted string
func (c *SCipher) AESDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
  block, err := aes.NewCipher(key)
  if err != nil {
    return ciphertext, nil
  }

  // The IV needs to be unique, but not secure. Therefore it's common to
  // include it at the beginning of the ciphertext.
  if len(ciphertext) < aes.BlockSize {
    return ciphertext, errors.New("len(ciphertext) < aes.BlockSize")
  }
  iv := ciphertext[:aes.BlockSize]
  ciphertext = ciphertext[aes.BlockSize:]
  stream := cipher.NewCFBDecrypter(block, iv)

  // XORKeyStream can work in-place if the two arguments are the same.
  stream.XORKeyStream(ciphertext, ciphertext)
  return ciphertext, nil
}

func (c *SCipher) SHA512(key []byte) ([]byte) {
  sha_512 := sha512.New()
  sha_512.Write(key)
  return sha_512.Sum(nil)
}

func (c *SCipher) SHA256(key []byte) ([]byte) {
  sha_256 := sha256.New()
  sha_256.Write(key)
  return sha_256.Sum(nil)
}

func (c *SCipher) Password2Key(password string) ([]byte) {
  dk, _ := scrypt.Key([]byte(password), c.SHA512([]byte(password)), 1<<15, 8, 1, 32)
  return dk
}
