package examples

import (
	"crypto/x509"
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
		log.Fatal(err)
	}

	metadata := baseca.CertificateRequest{
		CommonName:            "example.coinbase.com",
		SubjectAlternateNames: []string{"example.coinbase.com"},
		SigningAlgorithm:      x509.ECDSAWithSHA384,
		PublicKeyAlgorithm:    x509.ECDSA,
		KeySize:               256,
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
