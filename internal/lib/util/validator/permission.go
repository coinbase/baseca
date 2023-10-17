package validator

import "github.com/coinbase/baseca/internal/types"

func IsSupportedPermission(permission string) bool {
	switch permission {
	case types.ADMIN, types.PRIVILEGED, types.READ:
		return true
	}

	return false
}
