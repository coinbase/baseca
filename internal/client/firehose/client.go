package firehose

import (
	"context"
	"fmt"

	config_v2 "github.com/aws/aws-sdk-go-v2/config"
	firehose_v2 "github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/coinbase/baseca/internal/config"
)

type FirehoseClientIface interface {
	PutRecord(ctx context.Context, params *firehose_v2.PutRecordInput, optFns ...func(*firehose_v2.Options)) (*firehose_v2.PutRecordOutput, error)
}

type FirehoseClient struct {
	DataStream string
	Service    FirehoseClientIface
}

func NewFirehoseClient(config *config.Config) (*FirehoseClient, error) {
	cfg, err := config_v2.LoadDefaultConfig(context.TODO(),
		config_v2.WithRegion(config.Firehose.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create new session: %s", err)
	}

	return &FirehoseClient{
		DataStream: config.Firehose.Stream,
		Service:    firehose_v2.NewFromConfig(cfg),
	}, nil
}
