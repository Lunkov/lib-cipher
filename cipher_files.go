package cipher

import (
  "bytes"
  "io/ioutil"
  "encoding/gob"
  "github.com/golang/glog"
)

type CFile struct {
  Version    string 
  Data       []byte
  Hash       []byte
}

func NewCFile() *CFile {
  return &CFile{Version: "1"}
}

func (f *CFile) SaveFilePwd(filename string, password string, data []byte) (bool) {
  c := NewSCipher()
  return f.SaveFile(filename, c.Password2Key(password), data)
}

func (f *CFile) SaveFile(filename string, key []byte, data []byte) (bool) {
  c := NewSCipher()
  f.Hash = c.SHA512([]byte(f.Version + string(c.SHA512(data))))
  f.Data, _ = c.AESEncrypt(key, data)

  var buff bytes.Buffer
  encoder := gob.NewEncoder(&buff)
  encoder.Encode(f)

  err := ioutil.WriteFile(filename, buff.Bytes(), 0640) // just pass the file name
  if err != nil {
    glog.Errorf("ERR: SaveKey Write(%s): %v", filename, err)
    return false
  }
  return true
}

func (f *CFile) LoadFilePwd(filename string, password string) ([]byte, bool) {
  c := NewSCipher()
  return f.LoadFile(filename, c.Password2Key(password))
}

func (f *CFile) LoadFile(filename string, key []byte) ([]byte, bool) {
  data, err := ioutil.ReadFile(filename) 
  if err != nil {
    glog.Errorf("ERR: LoadFile (%s) err='%v'", filename, err)
    return nil, false
  }
  buf := bytes.NewBuffer(data)
  decoder := gob.NewDecoder(buf)
  err = decoder.Decode(f)
  if err != nil {
    glog.Errorf("ERR: gob.Decoder('%s'): GOB: %v", filename, err)
    return nil, false
  }
  c := NewSCipher()
  enc, ok := c.AESDecrypt(key, f.Data)
  if !ok {
    glog.Errorf("ERR: c.Decrypt('%s'): %v", filename, err)
    return nil, false
  }
  hash := c.SHA512([]byte(f.Version + string(c.SHA512(enc))))
  if bytes.Compare(hash, f.Hash) != 0 {
    glog.Errorf("ERR: c.Hash('%s'): %v", filename, err)
    return nil, false
  }
  return enc, true
}
