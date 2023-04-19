package cipher

import (
  "bytes"
  "encoding/gob"
  "math/big"

  "crypto/rand"
	"crypto/ecdsa"
	"crypto/elliptic"
  "crypto/sha512"
  
  "github.com/golang/glog"
)

type ECDSAPublicKeyBuf struct {
  Type string
  X, Y []byte
}

func ECDSAGetParams(t string) (elliptic.Curve, bool) {
  var params elliptic.Curve
  switch t {
    case "P-224":
      params = elliptic.P224()
      break
    case "P-256":
      params = elliptic.P256()
      break
    case "P-384":
      params = elliptic.P384()
      break
    case "P-521":
      params = elliptic.P521()
      break
    default:
      glog.Errorf("ERR: Unrecognized cipher algorithm: '%s'", t)
      return nil, false
  }
  return params, true
}

func ECDSAPublicKeySerialize(public *ecdsa.PublicKey) ([]byte, bool) {
  ecdsabuf := ECDSAPublicKeyBuf{Type: public.Params().Name, X: public.X.Bytes(), Y: public.Y.Bytes()}
  var buff bytes.Buffer
  encoder := gob.NewEncoder(&buff)
  encoder.Encode(ecdsabuf)
  glog.Errorf("ERR: QQQQ: '%v'", public.Params())
  return buff.Bytes(), true
}

func ECDSAPublicKeyDeserialize(msg []byte) (*ecdsa.PublicKey, bool) {
  var ecdsabuf ECDSAPublicKeyBuf
  buf := bytes.NewBuffer(msg)
  decoder := gob.NewDecoder(buf)
  err := decoder.Decode(&ecdsabuf)
  if err != nil {
    glog.Errorf("ERR: decoder.Decode %v", err)
    return nil, false
  }
  curve, ok := ECDSAGetParams(ecdsabuf.Type)
  if !ok {
    return nil, false
  }
  x := big.Int{}
  y := big.Int{}
  x.SetBytes(ecdsabuf.X)
  y.SetBytes(ecdsabuf.Y)
  return &ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}, true
}

func ECDSADeserializeAndVerify(pk []byte, message []byte, signature []byte) bool {
  public, ok := ECDSAPublicKeyDeserialize(pk)
  if !ok {
    return false
  }
  hashed := sha512.Sum512(message)
  return ecdsa.VerifyASN1(public, hashed[:], signature)
}

func ECDSASign(pk *ecdsa.PrivateKey, message []byte) ([]byte, bool) {
  hashed := sha512.Sum512(message)
  signature, err := ecdsa.SignASN1(rand.Reader, pk, hashed[:])
  return signature, err == nil 
}
