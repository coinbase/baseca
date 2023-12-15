package validator

import "github.com/coinbase/baseca/internal/types"

func IsSupportedPermission(permission string) bool {
	switch permission {
	case types.ADMIN.String(), types.PRIVILEGED.String(), types.READ.String():
		return true
	}

	return false
}
