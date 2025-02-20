package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func LoadPrivateKey() *rsa.PrivateKey {
	idpKeyPEM, err := os.ReadFile("idp-key.pem")
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(idpKeyPEM)
	privKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return privKeyInterface.(*rsa.PrivateKey)
}
