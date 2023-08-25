package examples

import (
	"crypto/x509"
	"fmt"
	"log"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	baseca "github.com/coinbase/baseca/pkg/client"
)

func OperationsSignCSR() {
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

	certAuth := apiv1.CertificateAuthorityParameter{
		Region:        "us-east-1",
		CaArn:         "arn:aws:acm-pca:us-east-1:1123331122:certificate-authority/112311-111231-1123131-11231",
		SignAlgorithm: "SHA512WITHRSA",
		AssumeRole:    false,
		Validity:      30,
	}

	certificateRequest := baseca.CertificateRequest{
		CommonName:            "example.coinbase.com",
		SubjectAlternateNames: []string{"example.coinbase.com"},
		SigningAlgorithm:      x509.SHA384WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		KeySize:               4096,
		Output: baseca.Output{
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
