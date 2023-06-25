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
  assert.False(t, privok)
  privok = rkpriv.LoadPrivateKey("123", "./test/test.key.sec") 
  assert.True(t, privok)


  rkpub := NewACipherRSA("RSA4096")
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
