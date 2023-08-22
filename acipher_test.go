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
  assert.NotNil(t, privok)
  privok = rkpriv.LoadPrivateKey("123", "./test/test.key.sec") 
  assert.Nil(t, privok)


  rkpub := NewACipher("RSA4096")
  pubok := rkpub.LoadPublicKey("./test/test.key.pub") 
  assert.Nil(t, pubok)
  
  msg := ([]byte)("This Message for Sign")
  sign, signok := rkpriv.Sign(msg)
  assert.Nil(t, signok)
  
  vok, errv := rkpub.Verify(msg, sign)
  assert.True(t, vok)
  assert.Nil(t, errv)
  
  enc, encok := rkpub.EncryptWithPublicKey(msg)
  assert.Nil(t, encok)
  
  dec, decok := rkpriv.DecryptWithPrivateKey(enc)
  assert.Nil(t, decok)
  assert.Equal(t, msg, dec)
}

func TestSyncCrypt(t *testing.T) {
  msg := ([]byte)("This Message for Encrypt")
  
  rks := NewSCipher()
  key := rks.SHA256(([]byte)("Big password"))
  keyw := rks.SHA256(([]byte)("Wrong password"))
  
  encs, encsok := rks.AESEncrypt(key, msg)
  assert.Nil(t, encsok)

  encs2 := make([]byte, len(encs))
  copy(encs2, encs)
  decsw, decsokw := rks.AESDecrypt(keyw, encs2)
  // TODO !!! Wrong Password
  //assert.False(t, decsokw)
  assert.Nil(t, decsokw)
  assert.NotEqual(t, msg, decsw)  
  
  decs, decsok := rks.AESDecrypt(key, encs)
  assert.Nil(t, decsok)
  assert.Equal(t, msg, decs)
}

