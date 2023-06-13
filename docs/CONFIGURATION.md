# `baseca` Configuration File

## Environment Variables

Configurations are held the [`baseca/config`](../config/). The structure for the configuration files are `config.primary.CONFIGURATION.ENVIRONMENT.yml`.

- If `ENVIRONMENT` is set to anything the value will be `aws`, if it is not set it will be `sandbox`.
- If `CONFIGURATION` is set, that same value will reflect within the configuration file.

If `baseca` is run with the following environment variables then during start time it will look for the `config.primary.infrastructure-production.aws.yml` configuration file.

```sh
export ENVIRONMENT=production
export CONFIGURATION=infrastructure-production
```

## Configuration File Parameters

```yml
grpc_server_address: 0.0.0.0:9090 # baseca gRPC Server Port

ocsp_server: # Optional
  - production.ocsp.example.com # Custom OCSP Server URL

database:
  database_driver: postgres # Do Not Modify
  database_table: baseca # Database Table Name
  database_endpoint: xxxxxx.cluster.xxxxxx.us-east-1.rds.amazonaws.com # Database Writer Endpoint 
  database_reader_endpoint: xxxxxx.cluster-ro.xxxxxx.us-east-1.rds.amazonaws.com # Database Reader Endpoint
  database_user: root # Database User
  database_port: 5432 # Database Port
  region: us-east-1 # RDS Region
  ssl_mode: verify-full # RDS SSL Mode

redis:
  cluster_endpoint: xxxxxx.xxxxxx.0001.use1.cache.amazonaws.com # Redis Endpoint
  port: 6379 # Redis Port
  rate_limit: 20 # 5-minute Sliding Window Rate Limit per Subject Alternative Name (SAN) 

domains:
  - example.com # Domains baseca Can Issue Certificates

acm_pca:
  # Alias for Certificate Authority (production_use1)
  production_use1:
    region: us-east-1 # Region Private CA is Deployed In
    ca_arn: arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx # Private CA ARN
    ca_active_day: 90 # Days Subordinate CA Issued from baseca is Active
    assume_role: false # baseca Supports Cross-Account Access to Private CA; if baseca is deployed in a different account than the Private CA set this to true.
    root_ca: false # Root CA or Subordinate CA

  # Alias for Certificate Authority (production_usw1)
  production_usw1:
    region: us-west-1
    ca_arn: arn:aws:acm-pca:us-west-1:123456789012:certificate-authority/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    ca_active_day: 180
    assume_role: false
    root_ca: false

   # Alias for Certificate Authority (development_use1)
  development_use1:
    region: us-east-1
    ca_arn: arn:aws:acm-pca:us-east-1:987654321098:certificate-authority/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    ca_active_day: 180
    assume_role: true
    role_arn: arn:aws:iam::987654321098:role/[ROLE]
    root_ca: false

firehose:
  stream: baseca-production # Kinesis Firehose Stream Name
  region: us-east-1 # Kinesis Firehose Region

kms:
  key_id: 12345678-1234-1234-1234-123456789012 # KMS Key ID for Signing and Validating Requests
  signing_algorithm: RSASSA_PSS_SHA_512  # [RSASSA_PKCS1_V1_5_SHA_256, RSASSA_PKCS1_V1_5_SHA_384, RSASSA_PKCS1_V1_5_SHA_512, RSASSA_PSS_SHA_256, RSASSA_PSS_SHA_384, RSASSA_PSS_SHA_512]
  region: us-east-1 # KMS Region
  auth_validity: 5 # User Authentication Token Validity (Minutes) 

secrets_manager:
  secret_id: baseca-xxxxxxxxxxxx # AWS Secrets Manager ID

subordinate_ca_metadata:
  # baseca Subordinate CA Metadata
  country: "US"
  province: "CA"
  locality: "San Francisco"
  organization: "Example"
  organization_unit: "Security"
  email: "example@example.com"

  # [RSA, ECDSA]
  key_algorithm: "RSA" 

  # RSA [SHA256WITHRSA, SHA384WITHRSA, SHA512WITHRSA]
  # ECDSA [SHA256WITHECDSA, SHA384WITHECDSA, SHA512WITHECDSA]
  signing_algorithm: SHA512WITHRSA  

  # RSA [2048, 4096] 
  # ECDSA [256, 384, 521]
  key_size: 4096 

certificate_authority: # CA Environments: [local, sandbox, development, staging, pre_production, production, corporate]. Each value within the environment maps to the CA configured within acm_pca.
  
  # List of Development Certificate Authority Alias
  development:
    - development_use1
  
  # List of Production Certificate Authority Alias
  production:
    - production_use1
    - production_usw1
```

