package examples

import (
	"crypto/x509"
	"fmt"
	"log"

	baseca "github.com/coinbase/baseca/pkg/client"
)

func SignCSR() {
	configuration := baseca.Configuration{
		URL:         "localhost:9090",
		Environment: baseca.Env.Local,
	}

	authentication := baseca.Authentication{
		ClientId:    "CLIENT_ID",
		ClientToken: "CLIENT_TOKEN",
	}

	client, err := baseca.LoadDefaultConfiguration(configuration, baseca.Attestation.Local, authentication)
	if err != nil {
		fmt.Println(err)
	}

	metadata := baseca.CertificateRequest{
		CommonName:            "sandbox.coinbase.com",
		SubjectAlternateNames: []string{"sandbox.coinbase.com"},
		SigningAlgorithm:      x509.SHA384WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		KeySize:               4096,
		DistinguishedName: baseca.DistinguishedName{
			Organization: []string{"Coinbase"},
			// Additional Fields
		},
		Output: baseca.Output{
			PrivateKey:                   "/tmp/private.key",
			Certificate:                  "/tmp/certificate.crt",
			IntermediateCertificateChain: "/tmp/intermediate_chain.crt",
			RootCertificateChain:         "/tmp/root_chain.crt",
			CertificateSigningRequest:    "/tmp/certificate_request.csr",
		},
	}

	response, err := client.IssueCertificate(metadata)

	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%+v", response)
}
