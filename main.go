/*
Usage: cat /path/to/private-key.xml | go run main.go

Optionally takes base64 encoded input.

This is a very crude implementation. Any errors result in a panic.
*/
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io"
	"math/big"
	"os"
)

func chkErr(err error) {
	if err != nil {
		panic(err)
	}
}

type XMLRSAKey struct {
	Modulus  string
	Exponent string
	P        string
	Q        string
	DP       string
	DQ       string
	InverseQ string
	D        string
}

func b64d(str string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(str)
	chkErr(err)
	return []byte(decoded)
}

func b64bigint(str string) *big.Int {
	bint := &big.Int{}
	bint.SetBytes(b64d(str))
	return bint
}

func main() {
	xmlbs, err := io.ReadAll(os.Stdin)
	chkErr(err)

	if decoded, err := base64.StdEncoding.DecodeString(string(xmlbs)); err == nil {
		xmlbs = decoded
	}

	xrk := XMLRSAKey{}
	chkErr(xml.Unmarshal(xmlbs, &xrk))

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: b64bigint(xrk.Modulus),
			E: int(b64bigint(xrk.Exponent).Int64()),
		},
		D:      b64bigint(xrk.D),
		Primes: []*big.Int{b64bigint(xrk.P), b64bigint(xrk.Q)},
		Precomputed: rsa.PrecomputedValues{
			Dp:        b64bigint(xrk.DP),
			Dq:        b64bigint(xrk.DQ),
			Qinv:      b64bigint(xrk.InverseQ),
			CRTValues: ([]rsa.CRTValue)(nil),
		},
	}

	pemblock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	chkErr(pem.Encode(os.Stdout, pemblock))
}
