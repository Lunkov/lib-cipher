package cipher

import (
  "testing"
  "github.com/stretchr/testify/assert"
)

func TestCryptFile(t *testing.T) {
  fl := NewCFile()
  assert.True(t, fl.SaveFilePwd("./test.file", "1234567890", []byte("0987654321")))
  
  buf, ok := fl.LoadFilePwd("./test.file", "1234567890")
  
  assert.True(t, ok)

  assert.Equal(t, "0987654321", string(buf))
}

func TestCryptFileBuf(t *testing.T) {
  fl := NewCFile()
  bufe, oke := fl.EncryptBufPwd([]byte("1234567890"), "0987654321")
  assert.True(t, oke)
  
  bufd, okd := fl.DecryptBufPwd(bufe, "1234567890")
  
  assert.False(t, okd)

  bufd, okd = fl.DecryptBufPwd(bufe, "0987654321")

  assert.Equal(t, "1234567890", string(bufd))
}
