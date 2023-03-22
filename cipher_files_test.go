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

