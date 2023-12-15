package ec2

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/gogo/status"
	"google.golang.org/grpc/codes"
)

var (
	instanceFilters = []types.Filter{
		{
			Name: aws.String("instance-state-name"),
			Values: []string{
				"pending",
				"running",
			},
		},
	}
)

func QueryInstanceMetadata(ctx context.Context, c *ec2.Client, instanceIds []string) (*types.Instance, error) {
	instancesDesc, err := c.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{
		InstanceIds: instanceIds,
		Filters:     instanceFilters,
	})
	if err != nil {
		return nil, fmt.Errorf("ec2 describe instances failed, %s", err)
	}

	if len(instancesDesc.Reservations) < 1 {
		return &types.Instance{}, status.Error(codes.Internal, "failed to query AWS via describe-instances: returned no reservations")
	}

	if len(instancesDesc.Reservations[0].Instances) < 1 {
		return &types.Instance{}, status.Error(codes.Internal, "failed to query AWS via describe-instances: returned no instances")
	}

	return &instancesDesc.Reservations[0].Instances[0], nil
}
