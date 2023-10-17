package aws_iid

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

const (
	instance_identity_metadata  = "http://169.254.169.254/latest/dynamic/instance-identity/document"
	instance_identity_signature = "http://169.254.169.254/latest/dynamic/instance-identity/signature"
)

type EC2InstanceMetadata struct {
	InstanceIdentityDocument  []byte `json:"instance_identity_document"`
	InstanceIdentitySignature []byte `json:"instance_identity_signature"`
}

func BuildInstanceMetadata() (*string, error) {
	instance_metadata, err := httpGetRequest(instance_identity_metadata)
	if err != nil {
		return nil, err
	}

	rsa_signature, err := httpGetRequest(instance_identity_signature)
	if err != nil {
		return nil, err
	}

	metadata := EC2InstanceMetadata{
		InstanceIdentityDocument:  instance_metadata,
		InstanceIdentitySignature: rsa_signature,
	}

	metadata_json, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}

	output := bytes.NewBuffer(metadata_json).String()
	return &output, err
}

func httpGetRequest(uri string) ([]byte, error) {
	response, err := http.Get(uri) // #nosec G107 False Positive
	if err != nil {
		return nil, err
	} else {
		defer response.Body.Close() // #nosec G307 False Positive
		response, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}
