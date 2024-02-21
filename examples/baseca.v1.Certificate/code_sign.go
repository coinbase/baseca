package examples

import (
	"crypto/x509"
	"log"

	baseca "github.com/coinbase/baseca/pkg/client"
	"github.com/coinbase/baseca/pkg/types"
)

func CodeSign() {
	client, err := baseca.NewClient("localhost:9090", baseca.Attestation.Local,
		baseca.WithClientId("CLIENT_ID"), baseca.WithClientToken("CLIENT_TOKEN"),
		baseca.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	metadata := types.Signature{
		CertificateRequest: types.CertificateRequest{
			CommonName:            "example.coinbase.com",
			SubjectAlternateNames: []string{"example.coinbase.com"},
			SigningAlgorithm:      x509.ECDSAWithSHA512,
			PublicKeyAlgorithm:    x509.ECDSA,
			KeySize:               256,
			Output: types.Output{
				PrivateKey:                   "/tmp/private.key",
				Certificate:                  "/tmp/certificate.crt",
				IntermediateCertificateChain: "/tmp/intermediate_chain.crt",
				RootCertificateChain:         "/tmp/root_chain.crt",
				CertificateSigningRequest:    "/tmp/certificate_request.csr",
			},
			DistinguishedName: types.DistinguishedName{
				Organization: []string{"Coinbase"},
			},
		},
		SigningAlgorithm: x509.ECDSAWithSHA512,
		Data: types.Data{
			Path: types.Path{
				File:   "/path/to/artifact",
				Buffer: 4096,
			},
		},
	}

	signature, chain, err := client.GenerateSignature(metadata)
	if err != nil {
		log.Fatal(err)
	}

	// Validation Happens on Different Server
	manifest := types.Manifest{
		CertificateChain: chain,
		Signature:        signature,
		SigningAlgorithm: x509.ECDSAWithSHA512,
		Data: types.Data{
			Path: types.Path{
				File:   "/path/to/artifact",
				Buffer: 4096,
			},
		},
	}

	tc := types.TrustChain{
		CommonName:                "example.coinbase.com",
		CertificateAuthorityFiles: []string{"/path/to/intermetidate.crt"},
	}

	err = baseca.ValidateSignature(tc, manifest)
	if err != nil {
		log.Fatal(err)
	}

	log.Print("Signature Verified")
}
