package main

import (
	"crypto/x509"
	"fmt"
	"log"

	baseca "github.com/coinbase/baseca/pkg/client"
)

func main() {
	// LEARNING
	client_id := "ec650cf6-438b-4c5e-a01e-8ba089e08678"
	client_token := "vQlY9n#R,tqMF:ld~Q+#@f=9e9dbrxdP"

	// LOCAL
	// client_id := "75b689fa-1906-4fc7-b6b1-4facb39a6342"
	// client_token := "\u0026mJr6K0n\u003c@|.e#3YQ^byuV=4Mf{x{7K2"

	configuration := baseca.Configuration{
		URL:         "3.91.238.24:9090",
		Environment: baseca.Env.Local,
	}

	// configuration := baseca.Configuration{
	// 	URL:         "localhost:9090",
	// 	Environment: baseca.Env.Local,
	// }

	client, err := baseca.LoadDefaultConfiguration(configuration, client_id, client_token, baseca.Attestation.Local)
	if err != nil {
		fmt.Println(err)
	}

	metadata := baseca.CertificateRequest{
		CommonName:            "test.example.com",
		SubjectAlternateNames: []string{"test.example.com"},
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

	response, err := client.IssueCertificate(metadata)

	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%+v", response)
}
