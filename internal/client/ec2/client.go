package ec2

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type EC2ClientIface interface {
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

type EC2Client struct {
	Service EC2ClientIface
}

func NewEC2Client(region string, roleArn string) (*ec2.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load ec2 sdk config, %v", err)
	}

	stsClient := sts.NewFromConfig(cfg)
	credentials := stscreds.NewAssumeRoleProvider(stsClient, roleArn)

	assumedRoleConfig := aws.Config{
		Credentials: aws.NewCredentialsCache(credentials),
		Region:      cfg.Region,
	}

	return ec2.NewFromConfig(assumedRoleConfig), nil
}
