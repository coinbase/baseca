package util

const (
	ERROR_HASHING_CREDENTIALS = "error hashing user credentials" // #nosec G101 False Positive
	ERROR_CREATE_TOKEN        = "error creating auth token"
	ERROR_LOCKFILE_PRESENT    = "subordinate ca lockfile present"
	INVALID_SERIAL_NUMBER     = "invalid serial number for enrollment"
	ERROR_ENROLLING_DEVICE    = "error enrolling device serial number"
	MALFORMATTED_REQUEST      = "malformatted request parameters"
	UNAUTHORIZED_REQUEST      = "unauthorized request"
)
