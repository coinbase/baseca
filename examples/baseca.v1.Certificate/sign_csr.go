package examples

import (
	"crypto/x509"
	"log"

	baseca "github.com/coinbase/baseca/pkg/client"
	"github.com/coinbase/baseca/pkg/types"
)

func SignCSR() {
	client, err := baseca.NewClient("localhost:9090", baseca.Attestation.Local,
		baseca.WithClientId("CLIENT_ID"), baseca.WithClientToken("CLIENT_TOKEN"),
		baseca.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	metadata := types.CertificateRequest{
		CommonName:            "example.coinbase.com",
		SubjectAlternateNames: []string{"example.coinbase.com"},
		SigningAlgorithm:      x509.ECDSAWithSHA384,
		PublicKeyAlgorithm:    x509.ECDSA,
		KeySize:               256,
		DistinguishedName: types.DistinguishedName{
			Organization:       []string{"Coinbase"},
			Locality:           []string{"San Francisco"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			OrganizationalUnit: []string{"Security"},
			// Additional Fields
		},
		Output: types.Output{
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
