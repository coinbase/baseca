package examples

import (
	"crypto/x509"
	"fmt"
	"os"

	baseca "github.com/coinbase/baseca/pkg/client"
	"github.com/coinbase/baseca/pkg/types"
)

func CodeSign() {
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

	data, _ := os.ReadFile("/bin/chmod")
	signature, chain, err := client.GenerateSignature(metadata, data)
	if err != nil {
		panic(err)
	}

	// Validation Happens on Different Server
	manifest := types.Manifest{
		CertificateChain: chain,
		Signature:        *signature,
		Data:             data,
		SigningAlgorithm: x509.SHA256WithRSA,
	}

	tc := types.TrustChain{
		CommonName:                "sandbox.coinbase.com",
		CertificateAuthorityFiles: []string{"/path/to/intermediate.pem"},
	}

	err = client.ValidateSignature(tc, manifest)
	if err != nil {
		panic(err)
	}

	fmt.Println("Signature Verified")
}
