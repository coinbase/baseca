package types

type ContextKey uint

const (
	// Context Metadata
	ServiceAuthenticationContextKey ContextKey = iota
	ProvisionerAuthenticationContextKey
	UserAuthenticationContextKey
)

type UserKey uint

const (
	// User Permissions
	ADMIN UserKey = iota
	PRIVILEGED
	READ
)

func (u UserKey) String() string {
	return [...]string{
		"ADMIN",
		"PRIVILEGED",
		"READ",
	}[u]
}

type AuthenticationKey uint

const (
	PassAuthentication AuthenticationKey = iota
	ServiceAuthentication
	ProvisionerAuthentication
)

var Methods = map[string]AuthenticationKey{
	"/grpc.health.v1.Health/Check":                       PassAuthentication,
	"/baseca.v1.Account/LoginUser":                       PassAuthentication,
	"/baseca.v1.Account/UpdateUserCredentials":           PassAuthentication,
	"/baseca.v1.Certificate/SignCSR":                     ServiceAuthentication,
	"/baseca.v1.Certificate/OperationsSignCSR":           ProvisionerAuthentication,
	"/baseca.v1.Certificate/QueryCertificateMetadata":    ProvisionerAuthentication,
	"/baseca.v1.Service/ProvisionServiceAccount":         ProvisionerAuthentication,
	"/baseca.v1.Service/GetServiceAccountByMetadata":     ProvisionerAuthentication,
	"/baseca.v1.Service/DeleteProvisionedServiceAccount": ProvisionerAuthentication,
}
