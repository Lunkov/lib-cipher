package cipher

import (
  "errors"
  "bytes"
  "os"
  "encoding/gob"
)

type CFile struct {
  Version    string 
  Data       []byte
  Hash       []byte
}

func NewCFile() *CFile {
  return &CFile{Version: "1"}
}

func (f *CFile) SaveFilePwd(filename string, password string, data []byte) (error) {
  c := NewSCipher()
  return f.SaveFile(filename, c.Password2Key(password), data)
}

func (f *CFile) SaveFile(filename string, key []byte, data []byte) (error) {
  var err error
  c := NewSCipher()
  f.Hash = c.SHA512([]byte(f.Version + string(c.SHA512(data))))
  f.Data, err = c.AESEncrypt(key, data)
  if err != nil {
    return err
  }

  var buff bytes.Buffer
  encoder := gob.NewEncoder(&buff)
  encoder.Encode(f)

  err = os.WriteFile(filename, buff.Bytes(), 0640) // just pass the file name
  if err != nil {
    return err
  }
  return nil
}

func (f *CFile) EncryptBufferPwd(password string, data []byte) (bytes.Buffer, error) {
  var err error
  var buff bytes.Buffer
  
  c := NewSCipher()
  f.Hash = c.SHA512([]byte(f.Version + string(c.SHA512(data))))
  f.Data, err = c.AESEncrypt(c.Password2Key(password), data)
  if err != nil {
    return buff, err
  }

  encoder := gob.NewEncoder(&buff)
  encoder.Encode(f)

  return buff, nil
}

func (f *CFile) DecryptBufferPwd(password string, data *bytes.Buffer) ([]byte, error) {
  decoder := gob.NewDecoder(data)
  err := decoder.Decode(f)
  if err != nil {
    return nil, err
  }
  c := NewSCipher()
  enc, errd := c.AESDecrypt(c.Password2Key(password), f.Data)
  if errd != nil {
    return nil, errd
  }
  hash := c.SHA512([]byte(f.Version + string(c.SHA512(enc))))
  if bytes.Compare(hash, f.Hash) != 0 {
    return nil, errors.New("Wrong Hash")
  }
  return enc, nil
}

func (f *CFile) LoadFilePwd(filename string, password string) ([]byte, error) {
  c := NewSCipher()
  return f.LoadFile(filename, c.Password2Key(password))
}

func (f *CFile) LoadFile(filename string, key []byte) ([]byte, error) {
  data, err := os.ReadFile(filename) 
  if err != nil {
    return nil, err
  }
  buf := bytes.NewBuffer(data)
  decoder := gob.NewDecoder(buf)
  err = decoder.Decode(f)
  if err != nil {
    return nil, err
  }
  c := NewSCipher()
  enc, errd := c.AESDecrypt(key, f.Data)
  if errd != nil {
    return nil, errd
  }
  hash := c.SHA512([]byte(f.Version + string(c.SHA512(enc))))
  if bytes.Compare(hash, f.Hash) != 0 {
    return nil, errors.New("Wrong Hash")
  }
  return enc, nil
}

func (f *CFile) EncryptBufPwd(data []byte, password string) ([]byte, error) {
  c := NewSCipher()
  return f.EncryptBuf(data, c.Password2Key(password))
}

func (f *CFile) EncryptBuf(data []byte, key []byte) ([]byte, error) {
  var err error
  c := NewSCipher()
  f.Hash = c.SHA512([]byte(f.Version + string(c.SHA512(data))))
  f.Data, err = c.AESEncrypt(key, data)
  if err != nil {
    return nil, err
  }
  var buff bytes.Buffer
  encoder := gob.NewEncoder(&buff)
  encoder.Encode(f)
  return buff.Bytes(), nil
}

func (f *CFile) DecryptBufPwd(data []byte, password string) ([]byte, error) {
  c := NewSCipher()
  return f.DecryptBuf(data, c.Password2Key(password))
}

func (f *CFile) DecryptBuf(data []byte, key []byte) ([]byte, error) {
  buf := bytes.NewBuffer(data)
  decoder := gob.NewDecoder(buf)
  err := decoder.Decode(f)
  if err != nil {
    return nil, err
  }
  c := NewSCipher()
  enc, errd := c.AESDecrypt(key, f.Data)
  if errd != nil {
    return nil, errd
  }
  hash := c.SHA512([]byte(f.Version + string(c.SHA512(enc))))
  if bytes.Compare(hash, f.Hash) != 0 {
    return nil, errors.New("Decrypt: Wrong Hash")
  }
  return enc, nil
}
