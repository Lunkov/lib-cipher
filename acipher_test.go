package cipher

import (
  "testing"
  "github.com/stretchr/testify/assert"
)

func TestAsyncCrypt(t *testing.T) {
  rk := NewACipher("RSA4096")
  rk.GenerateKeyPair()
  rk.SavePublicKey("./test/test.key.pub")
  rk.SavePrivateKey("123", "./test/test.key.sec")
  
  rkpriv := NewACipher("RSA4096")
  privok := rkpriv.LoadPrivateKey("1233", "./test/test.key.sec") 
  assert.False(t, privok)
  privok = rkpriv.LoadPrivateKey("123", "./test/test.key.sec") 
  assert.True(t, privok)


  rkpub := NewACipher("RSA4096")
  pubok := rkpub.LoadPublicKey("./test/test.key.pub") 
  assert.True(t,pubok)
  
  msg := ([]byte)("This Message for Sign")
  sign, signok := rkpriv.Sign(msg)
  assert.True(t, signok)
  
  vok := rkpub.Verify(msg, sign)
  assert.True(t, vok)
  
  enc, encok := rkpub.EncryptWithPublicKey(msg)
  assert.True(t, encok)
  
  dec, decok := rkpriv.DecryptWithPrivateKey(enc)
  assert.True(t, decok)
  assert.Equal(t, msg, dec)
}

func TestSyncCrypt(t *testing.T) {
  msg := ([]byte)("This Message for Encrypt")
  
  rks := NewSCipher()
  key := rks.SHA256(([]byte)("Big password"))
  keyw := rks.SHA256(([]byte)("Wrong password"))
  
  encs, encsok := rks.AESEncrypt(key, msg)
  assert.True(t, encsok)

  encs2 := make([]byte, len(encs))
  copy(encs2, encs)
  decsw, decsokw := rks.AESDecrypt(keyw, encs2)
  // TODO !!! Wrong Password
  //assert.False(t, decsokw)
  assert.True(t, decsokw)
  assert.NotEqual(t, msg, decsw)  
  
  decs, decsok := rks.AESDecrypt(key, encs)
  assert.True(t, decsok)
  assert.Equal(t, msg, decs)
}

