package types

type ContextKey int

const (
	// Context Metadata
	ServiceAuthenticationContextKey     ContextKey = iota
	ProvisionerAuthenticationContextKey ContextKey = iota
	UserAuthenticationContextKey        ContextKey = iota
	EnrollmentAuthenticationContextKey  ContextKey = iota

	// User Permissions
	ADMIN      = "ADMIN"
	PRIVILEGED = "PRIVILEGED"
	READ       = "READ"
)
