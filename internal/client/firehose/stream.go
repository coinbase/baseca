package firehose

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	firehose_v2 "github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/firehose/types"
)

type ForwardedEventUploadEvent struct {
	SerialNumber string   `json:"serial_number"`
	Metadata     Metadata `json:"metadata"`
}

type Metadata struct {
	CommonName              string    `json:"common_name"`
	SubjectAlternateName    []string  `json:"subject_alternate_name"`
	CertificateExpiration   time.Time `json:"certificate_expiration"`
	IssuedDate              time.Time `json:"issued_date"`
	CaSerialNumber          string    `json:"ca_serial_number"`
	CertificateAuthorityArn string    `json:"certificate_authority_arn"`
}

func (c FirehoseClient) Stream(ctx context.Context, event ForwardedEventUploadEvent) (response *firehose_v2.PutRecordOutput, err error) {
	batch, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("error marshalling firehose event: %s", err)
	}
	input := &firehose_v2.PutRecordInput{
		DeliveryStreamName: aws.String(c.DataStream),
		Record: &types.Record{
			Data: append(batch, '\n'),
		},
	}

	record, err := c.Service.PutRecord(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error putting firehose record: %s", err)
	}
	return record, nil
}
