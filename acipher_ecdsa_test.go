package cipher

import (
  "testing"
  "github.com/stretchr/testify/assert"
  
  "crypto/sha512"
  "crypto/ecdsa"

  "github.com/Lunkov/go-hdwallet"
)

func TestAsyncECDSA(t *testing.T) {
  // Generate Key and Save
  rk := NewACipherECDSA("P-521")
  rk.GenerateKeyPair()
  privok := rk.SavePublicKey("./test/test.p521.key.pub")
  assert.Nil(t, privok)
  privok = rk.SavePrivateKey("123", "./test/test.p521.key.sec")
  assert.Nil(t, privok)

  // Load Public Key
  rkpub := NewACipherECDSA("P-521")
  pubok := rkpub.LoadPublicKey("./test/test.p521.key.pub") 
  assert.Nil(t, pubok)
  
  // Load Private Key
  rkpriv := NewACipherECDSA("P-521")
  privok = rkpriv.LoadPrivateKey("1233", "./test/test.p521.key.sec") 
  assert.NotNil(t, privok)
  privok = rkpriv.LoadPrivateKey("123", "./test/test.p521.key.sec") 
  assert.Nil(t, privok)

  // Sign message with Private Key
  msg := ([]byte)("This Message for Sign")
  sign, signok := rkpriv.Sign(msg)
  assert.Nil(t, signok)
  
  // Verify message with Public Key
  vok, errv := rkpub.Verify(msg, sign)
  assert.True(t, vok)
  assert.Nil(t, errv)
}

func TestAsyncECDSASerialize(t *testing.T) {
  mnemonic := "chase oil pigeon elegant ketchup whip frozen beauty unknown brass amount slender pony pottery attitude flavor rifle primary beach sign glue oven crazy lottery"
  seed, _ := hdwallet.NewSeed(mnemonic, "", hdwallet.English)
  master, _ := hdwallet.NewKey(false, hdwallet.Seed(seed))
  
  wallet, _ := master.GetWallet(hdwallet.CoinType(hdwallet.ECOS))
  address, _ := wallet.GetAddress()
  assert.Equal(t, "0x5f7ae710cED588D42E863E9b55C7c51e56869963", address)
  
  pubKey := wallet.GetKey().PublicECDSA
  privKey := wallet.GetKey().PrivateECDSA
  //glog.Errorf("ERR: MASTER wallet='%v'", wallet.PublicKeyBytes())
  
  //pkBuf, okpk := PublicKeyToBytes(w.Master.PrivateECDSA)
  pkBuf, okpk := ECDSAPublicKeySerialize(pubKey)

	assert.Nil(t, okpk)
  assert.Equal(t, []byte{0x3d, 0xff, 0x81, 0x3, 0x1, 0x1, 0x11, 0x45, 0x43, 0x44, 0x53, 0x41, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x42, 0x75, 0x66, 0x1, 0xff, 0x82, 0x0, 0x1, 0x4, 0x1, 0x4, 0x54, 0x79, 0x70, 0x65, 0x1, 0xc, 0x0, 0x1, 0x1, 0x58, 0x1, 0xa, 0x0, 0x1, 0x1, 0x59, 0x1, 0xa, 0x0, 0x1, 0x4, 0x44, 0x61, 0x74, 0x61, 0x1, 0xa, 0x0, 0x0, 0x0, 0x4f, 0xff, 0x82, 0x1, 0x6, 0x57, 0x50, 0x2d, 0x32, 0x35, 0x36, 0x1, 0x20, 0xab, 0x9f, 0x33, 0xc5, 0x25, 0xd2, 0xff, 0x9c, 0x5f, 0x18, 0xd8, 0x50, 0xfc, 0x53, 0xf3, 0xa, 0xce, 0xa2, 0x96, 0x32, 0x7a, 0x6d, 0xbd, 0x19, 0xb6, 0xb5, 0x8c, 0x2f, 0x67, 0xad, 0x84, 0x5a, 0x1, 0x20, 0x55, 0xe, 0x8, 0x86, 0x6, 0x50, 0x26, 0x2b, 0x15, 0x4c, 0x79, 0xde, 0x61, 0xa2, 0x65, 0x15, 0x9c, 0xfb, 0xa0, 0xb3, 0xf4, 0x23, 0xb, 0xb9, 0x4d, 0xdb, 0x23, 0xf2, 0x8d, 0x89, 0x30, 0x77, 0x0}, pkBuf)
  
  message := []byte("Hello world")
  signature, sok := ECDSASign(privKey, message)
  assert.Nil(t, sok)
  
  hashed := sha512.Sum512(message)
  vok1 := ecdsa.VerifyASN1(pubKey, hashed[:], signature)
  assert.True(t, vok1)
  
  vok, errv := ECDSADeserializeAndVerify(pkBuf, message, signature)
  assert.True(t, vok)
  assert.Nil(t, errv)
  
  /*
  ciph := NewACipherECDSA("")
  cpok := ciph.PublicKeyDeserialize(pkBuf)
  assert.True(t, cpok)
  vok2 := ciph.Verify(message, signature)
  assert.True(t, vok2)
  * */
}
