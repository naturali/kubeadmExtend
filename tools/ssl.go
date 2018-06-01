package tools

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/golang/glog"
)

// ReadKeyByte Is Func
func ReadKeyByte(data []byte) (key *rsa.PrivateKey) {
	block, _ := pem.Decode(data)
	if block == nil {
		glog.Fatalln("failed to parse certificate PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	CheckError(err)
	return
}

// ReadCertByte Is Func
func ReadCertByte(data []byte) (cert *x509.Certificate) {
	block, _ := pem.Decode(data)
	if block == nil {
		glog.Fatalln("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	CheckError(err)
	return
}

// ReadKeyFile Is Func
func ReadKeyFile(keyFilePath string) (key *rsa.PrivateKey) {
	Body, err := ioutil.ReadFile(keyFilePath)
	CheckError(err)

	return ReadKeyByte(Body)
}

// ReadCertFile Is Func
func ReadCertFile(certFilePath string) (cert *x509.Certificate) {
	Body, err := ioutil.ReadFile(certFilePath)
	CheckError(err)

	return ReadCertByte(Body)
}

// VerifyFunc Is Func
func VerifyFunc(ca, client *x509.Certificate) {
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: client.ExtKeyUsage,
	}

	if _, err := client.Verify(opts); err != nil {
		glog.Fatalln(err.Error())
	}
}
