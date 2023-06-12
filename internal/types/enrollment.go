package types

type DeviceEnrollmentRequest struct {
	SerialNumber string `json:"serial_number" binding:"required"`
	Environment  string `json:"environment" binding:"required,ca_environment"`
}

type DeviceEnrollmentResponse struct {
	SerialNumber string `json:"serial_number"`
	Credentials  string `json:"credentials"`
}

type EndpointCertificateIssueRequest struct {
}
