package aws

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"os"
)

func LoadAWSConfig(ctx context.Context, regionOverride string) (aws.Config, error) {
	var options []func(*config.LoadOptions) error

	// Only use profile if we're not in a K8s environment
	if !isInKubernetes() {
		options = append(options, config.WithSharedConfigProfile(getProfile()))
	}

	if regionOverride != "" {
		options = append(options, config.WithRegion(regionOverride))
	}

	return config.LoadDefaultConfig(ctx, options...)
}

// Simple check to see if we're running in K8s
func isInKubernetes() bool {
	// Check for the service account token file
	_, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	return err == nil
}

func getProfile() string {
	if profile := os.Getenv("AWS_PROFILE"); profile != "" {
		return profile
	}
	return "default"
}

func GetCallerIdentity(cfg aws.Config) (*sts.GetCallerIdentityOutput, error) {
	stsClient := sts.NewFromConfig(cfg)
	return stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
}
