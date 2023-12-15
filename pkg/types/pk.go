package types

type KeyType uint

const (
	RSA_PRIVATE_KEY KeyType = iota
	ECDSA_PRIVATE_KEY
	PKCS8_PRIVATE_KEY
	CERTIFICATE
	CERTIFICATE_REQUEST
	RSA
	ECDSA
	Ed25519
)

func (k KeyType) String() string {
	return [...]string{
		"RSA PRIVATE KEY",
		"EC PRIVATE KEY",
		"PRIVATE KEY",
		"CERTIFICATE",
		"CERTIFICATE REQUEST",
		"RSA",
		"ECDSA",
		"Ed25519"}[k]
}
