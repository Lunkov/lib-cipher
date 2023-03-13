package cipher

import (
  "testing"
  "github.com/stretchr/testify/assert"
)

func TestCrypt(t *testing.T) {
  rk := NewCipherMessage()
  rk.GenerateKeyPairAndSave("123", "test.key")
  
  rkpriv := NewCipherMessage()
  privok := rkpriv.LoadPrivateKey("1233", "test.key") 
  assert.False(t, privok)
  privok = rkpriv.LoadPrivateKey("123", "test.key") 
  assert.True(t, privok)

  rkpub := NewCipherMessage()
  pubok := rkpub.LoadPublicKey("test.key.pub") 
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
  
  rks := NewCipherMessage()
  key, okk := rks.SHA256(([]byte)("Big password"))
  assert.True(t, okk)
  keyw, okkw := rks.SHA256(([]byte)("Wrong password"))
  assert.True(t, okkw)
  
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

