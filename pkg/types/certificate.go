package types

import (
	"bytes"
	"encoding/pem"
)

type SigningRequest struct {
	CSR        *bytes.Buffer
	PrivateKey *pem.Block
}

type SignedCertificate struct {
	CertificatePath                  string
	IntermediateCertificateChainPath string
	RootCertificateChainPath         string
}
