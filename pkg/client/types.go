package baseca

import (
	"crypto/x509"
	"sync"
	"time"
)

var Attestation Provider = Provider{
	Local: "Local",
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

var iidCacheExpiration = 10 * time.Minute

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
	StreetAddress      []string
	PostalCode         []string
	SerialNumber       string
}

type Output struct {
	CertificateSigningRequest    string
	Certificate                  string
	IntermediateCertificateChain string
	RootCertificateChain         string
	PrivateKey                   string
}

type iidCache struct {
	expiration time.Time
	lock       sync.Mutex
	value      string
}
