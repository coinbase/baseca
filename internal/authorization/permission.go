package authorization

const (
	ADMIN      = "ADMIN"
	PRIVILEGED = "PRIVILEGED"
	READ       = "READ"
)

func IsSupportedPermission(permission string) bool {
	switch permission {
	case ADMIN, PRIVILEGED, READ:
		return true
	}

	return false
}
