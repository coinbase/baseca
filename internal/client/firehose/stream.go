package firehose

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	firehose_v2 "github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/coinbase/baseca/internal/lib/util"
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
	Timestamp               time.Time `json:"timestamp"`
}

func (c FirehoseClient) Stream(ctx context.Context, event ForwardedEventUploadEvent) (response *firehose_v2.PutRecordOutput, err error) {
	var firehoseErr error

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

	for _, backoff := range util.BackoffSchedule {
		record, err := c.Service.PutRecord(ctx, input)
		if err != nil {
			firehoseErr = err

			jitterInt, err := rand.Int(rand.Reader, big.NewInt(int64(backoff)))
			if err != nil {
				return nil, fmt.Errorf("error generating jitter: %s", err)
			}

			jitter := time.Duration(jitterInt.Int64())
			time.Sleep(backoff + jitter)

			continue
		}
		return record, nil
	}
	return nil, fmt.Errorf("error putting firehose record: %s", firehoseErr)
}
