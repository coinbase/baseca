package baseca

import "crypto/x509"

var Attestation Provider = Provider{
	Local: "NONE",
	AWS:   "AWS",
}

var Env = Environment{
	Local:         "Local",
	Sandbox:       "Sandbox",
	Development:   "Development",
	Staging:       "Staging",
	PreProduction: "PreProduction",
	Production:    "Production",
}

type Environment struct {
	Local         string
	Sandbox       string
	Development   string
	Staging       string
	PreProduction string
	Production    string
}

type Configuration struct {
	URL         string
	Environment string
}

type Provider struct {
	Local string
	AWS   string
}

type Authentication struct {
	ClientId    string
	ClientToken string
	AuthToken   string
}

type CertificateRequest struct {
	CommonName            string
	SubjectAlternateNames []string
	DistinguishedName     DistinguishedName
	SigningAlgorithm      x509.SignatureAlgorithm
	PublicKeyAlgorithm    x509.PublicKeyAlgorithm
	KeySize               int
	Output                Output
}

type DistinguishedName struct {
	Country            []string
	Province           []string
	Locality           []string
	Organization       []string
	OrganizationalUnit []string
}

type Output struct {
	CertificateSigningRequest    string
	Certificate                  string
	IntermediateCertificateChain string
	RootCertificateChain         string
	PrivateKey                   string
}
