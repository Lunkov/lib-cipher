package cipher

import (
  "errors"
  "bytes"
  "encoding/gob"
  "strconv"
  "math/big"

  "crypto/rand"
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/sha512"
  
  "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type ECDSAPublicKeyBuf struct {
  Type string
  X, Y, Data []byte
}

func ECDSAGetParams(t string) (elliptic.Curve, error) {
  var params elliptic.Curve
  switch t {
    case "P-224":
      params = elliptic.P224()
      break
    case "P-256":
      params = elliptic.P256()
      break
    case "WP-256":
      params = secp256k1.S256()
      break
    case "P-384":
      params = elliptic.P384()
      break
    case "P-521":
      params = elliptic.P521()
      break
    default:
      return nil, errors.New("Wrong ECDSA: " + t)
  }
  return params, nil
}

func ECDSAPublicKeySerialize(public *ecdsa.PublicKey) ([]byte, error) {
  t := public.Params().Name
  if t == "" {
    t = "WP-" + strconv.Itoa(public.Params().BitSize)
  }
  _, err := ECDSAGetParams(t)
  if err != nil {
    return nil, err 
  }
  ecdsabuf := ECDSAPublicKeyBuf{Type: t, X: public.X.Bytes(), Y: public.Y.Bytes()}
  var buff bytes.Buffer
  encoder := gob.NewEncoder(&buff)
  encoder.Encode(ecdsabuf)
  return buff.Bytes(), nil
}

func ECDSAPublicKeyDeserialize(msg []byte) (*ecdsa.PublicKey, error) {
  var ecdsabuf ECDSAPublicKeyBuf
  buf := bytes.NewBuffer(msg)
  decoder := gob.NewDecoder(buf)
  err := decoder.Decode(&ecdsabuf)
  if err != nil {
    return nil, err
  }
  curve, errp := ECDSAGetParams(ecdsabuf.Type)
  if errp != nil {
    return nil, errp
  }
  x := big.Int{}
  x.SetBytes(ecdsabuf.X)
  y := big.Int{}
  y.SetBytes(ecdsabuf.Y)
  return &ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}, nil
}

func ECDSADeserializeAndVerify(pk []byte, message []byte, signature []byte) (bool, error) {
  public, err := ECDSAPublicKeyDeserialize(pk)
  if err != nil {
    return false, err
  }
  hashed := sha512.Sum512(message)
  return ecdsa.VerifyASN1(public, hashed[:], signature), nil
}

func ECDSASign(pk *ecdsa.PrivateKey, message []byte) ([]byte, error) {
  hashed := sha512.Sum512(message)
  signature, err := ecdsa.SignASN1(rand.Reader, pk, hashed[:])
  return signature, err 
}
