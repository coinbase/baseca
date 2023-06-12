package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"

	baseca "github.com/coinbase/baseca/pkg/client"
)

func main() {
	client_id := "[CLIENT_ID]"
	client_token := "[CLIENT_TOKEN]"

	configuration := baseca.Configuration{
		URL:         "localhost:9090",
		Environment: baseca.Env.Local,
	}

	client, err := baseca.LoadDefaultConfiguration(configuration, client_id, client_token, baseca.Attestation.Local)
	if err != nil {
		fmt.Println(err)
	}

	metadata := baseca.CertificateRequest{
		CommonName:            "sandbox.coinbase.com",
		SubjectAlternateNames: []string{"sandbox.coinbase.com"},
		SigningAlgorithm:      x509.SHA384WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		KeySize:               4096,
		Output: baseca.Output{
			PrivateKey:                "/tmp/private.key",
			Certificate:               "/tmp/certificate.crt",
			CertificateChain:          "/tmp/certificate_chain.crt",
			CertificateSigningRequest: "/tmp/certificate_request.csr",
		},
	}

	data, _ := ioutil.ReadFile("/bin/chmod")
	signature, chain, err := client.GenerateSignature(metadata, data)
	if err != nil {
		panic(err)
	}

	// Validation Happens on Different Server
	err = client.ValidateSignature(chain, *signature, data, "sandbox.coinbase.com", "/path/to/system/root")
	if err != nil {
		panic(err)
	}

	fmt.Println("Signature Verified")
}
