package cipher

import (
  "testing"
  "github.com/stretchr/testify/assert"
)

func TestAsyncRSA(t *testing.T) {
  rk := NewACipherRSA("RSA4096")
  rk.GenerateKeyPair()
  rk.SavePublicKey("./test/test.key.pub")
  rk.SavePrivateKey("123", "./test/test.key.sec")
  
  rkpriv := NewACipherRSA("RSA4096")
  privok := rkpriv.LoadPrivateKey("1233", "./test/test.key.sec") 
  assert.NotNil(t, privok)
  privok = rkpriv.LoadPrivateKey("123", "./test/test.key.sec") 
  assert.Nil(t, privok)


  rkpub := NewACipherRSA("RSA4096")
  pubok := rkpub.LoadPublicKey("./test/test.key.pub") 
  assert.Nil(t,pubok)
  
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
