package cipher

import (
  "testing"
  "github.com/stretchr/testify/assert"
)

func TestCryptFile(t *testing.T) {
  fl := NewCFile()
  assert.Nil(t, fl.SaveFilePwd("./test.file", "1234567890", []byte("0987654321")))
  
  buf, ok := fl.LoadFilePwd("./test.file", "1234567890")
  
  assert.Nil(t, ok)

  assert.Equal(t, "0987654321", string(buf))
}

func TestCryptFileBuf(t *testing.T) {
  fl := NewCFile()
  bufe, oke := fl.EncryptBufPwd([]byte("1234567890"), "0987654321")
  assert.Nil(t, oke)
  
  bufd, okd := fl.DecryptBufPwd(bufe, "1234567890")
  
  assert.NotNil(t, okd)

  bufd, okd = fl.DecryptBufPwd(bufe, "0987654321")

  assert.Equal(t, "1234567890", string(bufd))
}

func TestCryptFileBuffer(t *testing.T) {
  fl := NewCFile()
  bufe, err := fl.EncryptBufferPwd("0987654321", []byte("1234567890"))
  assert.Nil(t, err)
  
  bufd, okd := fl.DecryptBufferPwd("1234567890", &bufe)
  
  assert.NotNil(t, okd)

  bufe, err = fl.EncryptBufferPwd("0987654321", []byte("1234567890"))
  assert.Nil(t, err)

  bufd, okd = fl.DecryptBufferPwd("0987654321", &bufe)
  assert.Nil(t, okd)
  assert.Equal(t, "1234567890", string(bufd))
}
