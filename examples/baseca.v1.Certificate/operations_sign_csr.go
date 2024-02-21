package examples

import (
	"crypto/x509"
	"log"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	baseca "github.com/coinbase/baseca/pkg/client"
	"github.com/coinbase/baseca/pkg/types"
)

func OperationsSignCSR() {
	client, err := baseca.NewClient("localhost:9090", baseca.Attestation.Local,
		baseca.WithClientId("CLIENT_ID"), baseca.WithClientToken("CLIENT_TOKEN"),
		baseca.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	certAuth := apiv1.CertificateAuthorityParameter{
		Region:        "us-east-1",
		CaArn:         "arn:aws:acm-pca:us-east-1:1123331122:certificate-authority/112311-111231-1123131-11231",
		SignAlgorithm: "SHA512WITHRSA",
		AssumeRole:    false,
		Validity:      30,
	}

	certificateRequest := types.CertificateRequest{
		CommonName:            "example.coinbase.com",
		SubjectAlternateNames: []string{"example.coinbase.com"},
		SigningAlgorithm:      x509.SHA384WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		KeySize:               4096,
		DistinguishedName: types.DistinguishedName{
			Organization: []string{"Coinbase"},
			// Additional Fields
		},
		Output: types.Output{
			PrivateKey:                   "/tmp/sandbox.key",
			CertificateSigningRequest:    "/tmp/sandbox.csr",
			Certificate:                  "/tmp/sandbox.crt",
			IntermediateCertificateChain: "/tmp/intermediate_chain.crt",
			RootCertificateChain:         "/tmp/root_chain.crt",
		},
	}

	res, err := client.ProvisionIssueCertificate(certificateRequest, &certAuth, "example", "development", "EndEntityServerAuthCertificate")

	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%+v", res)

}
