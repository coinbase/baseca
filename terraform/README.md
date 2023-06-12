# `baseca` Infrastructure

## Local Deployment Resources

| Variable      | Description                            | Type   | Optional | Default  | Example                                                                                                                                    |
| ------------- | -------------------------------------- | ------ | -------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `service`     | Terraform Resource Prefix              | string | true     | baseca   | coinbase                                                                                                                                   |
| `environment` | Service Environment                    | string | false    |          | development                                                                                                                                |
| `region`      | AWS Region to Deploy                   | string | false    |          | us-east-1                                                                                                                                  |
| `key_spec`    | KMS Customer Managed Key Spec          | string | true     | RSA_4096 | [`customer_master_key_spec`](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key#customer_master_key_spec) |
| `bucket`      | S3 Bucket Name (Kinesis Data Firehose) | string | false    |          | baseca-firehose-development                                                                                                                |

Example Local Deployment for `development/baseca` Module

```sh
# baseca/terraform/development/baseca.tf

module "baseca" {
  source      = "./baseca"
  service     = "baseca"
  environment = "development"
  region      = "us-east-1"
  key_spec    = "RSA_4096"
  bucket      = "baseca-firehose-example"
}
```

## Production Deployment Resources

| Variable          | Description                                                                                                      | Type         | Optional                               | Default  | Example                                                                                                                                                                                                                           |
| ----------------- | ---------------------------------------------------------------------------------------------------------------- | ------------ | -------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `service`         | Terraform Resource Prefix                                                                                        | string       | true                                   | baseca   | coinbase                                                                                                                                                                                                                          |
| `environment`     | Service Environment                                                                                              | string       | false                                  |          | production                                                                                                                                                                                                                        |
| `region`          | AWS Region to Deploy                                                                                             | string       | false                                  |          | us-east-1                                                                                                                                                                                                                         |
| `key_spec`        | KMS Customer Managed Key Spec                                                                                    | string       | true                                   | RSA_4096 | [`customer_master_key_spec`](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key#customer_master_key_spec)                                                                                        |
| `bucket`          | S3 Bucket Name                                                                                                   | string       | false                                  |          | baseca-firehose-production                                                                                                                                                                                                        |
| `acm_pca_arns`    | List of Private CA ARNs in Account                                                                               | list(string) | false                                  |          | ["arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"]<br><br>_**NOTE:** These are upstream Intermediate CA(s) from AWS Private CA `baseca` will be issuing Subordinate CAs from._ |
| `db_ingress_cidr` | IP CIDR Blocks for Ingress to RDS and Redis                                                                      | list(string) | Requires `db_ingress_sg` if Not Used   |          | ["10.0.0.1/24", "10.0.0.2/24"]                                                                                                                                                                                                    |
| `db_ingress_sg`   | Security Groups for Ingress to RDS and Redis                                                                     | list(string) | Requires `db_ingress_cidr` if Not Used |          | ["10.0.0.1/24", "10.0.0.2/24"]                                                                                                                                                                                                    |
| `db_subnet_ids`   | Private Subnets to Deploy RDS Cluster<br><br>_**NOTE:** Minimum of two subnets in different availability zones._ | list(string) | false                                  |          | ["subnet-01234567", "subnet-09876543"]                                                                                                                                                                                            |
| `vpc_id`          | VPC ID for Security Groups<br><br>_**NOTE:** `db_subnet_ids` must be within this VPC._                           | string       | false                                  |          | vpc-12345678                                                                                                                                                                                                                      |

Example Production Deployment for `production/baseca` Resource Module

```sh
# baseca/terraform/production/baseca.tf

module "baseca" {
  source = "./baseca"
  service = "baseca"
  environment = "production"
  region = "us-east-1"
  key_spec = "RSA_4096"
  bucket = "baseca-firehose-example"

  vpc_id = "vpc-xxxxxxxx"
  db_ingress_cidr = ["10.0.0.0/8"]
  db_subnet_ids = [
    "subnet-09876543",
    "subnet-12345678"
  ]

  acm_pca_arns = [
    "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "arn:aws:acm-pca:us-east-1:987654321098:certificate-authority/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
  ]
}
```

## Production Compute Deployment

**DISCLAIMER:** The compute deployment is a sample of how `baseca` can run within an environment; this is not intended to be run as is and will require your organization to design the deployment pipeline for your use case.

| Variable             | Description                                                                                                                                                                           | Type         | Optional | Default | Example                                                                                          |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | -------- | ------- | ------------------------------------------------------------------------------------------------ |
| `service`            | Terraform Resource Prefix                                                                                                                                                             | string       | true     | baseca  | coinbase                                                                                         |
| `environment`        | Service Environment                                                                                                                                                                   | string       | false    |         | production                                                                                       |
| `configuration`      | Determines which Configuration File `baseca` Reads<br><br>_**NOTE:** For example, a value of `production` will read the `config.primary.production.aws.yml` file._                    | string       | false    |         | production                                                                                       |
| `region`             | AWS Region to Deploy                                                                                                                                                                  | string       | false    |         | us-east-1                                                                                        |
| `vpc_id`             | VPC ID to Deploy ECS Service<br><br>_**NOTE:** `subnet_ids` and `db_subnet_ids` must be within this VPC._                                                                             | string       | false    |         | vpc-12345678                                                                                     |
| `subnet_ids`         | VPC Subnets to Deploy ECS Service<br><br>_**NOTE:** Multiple subnets must be in different availability zones. Subnets also must be routable to Private Subnets from `db_subnet_ids`._ | list(string) | false    |         | ["subnet-0123456789abcdef", "subnet-9876543210fedcba"]                                           |
| `public_ip`          | Assign Public IP for ECS Service<br><br>_**NOTE:** If `public_ip` is set to `true` the `subnet_ids` must be Public Subnets._                                                          | bool         | true     | false   | false                                                                                            |
| `network_ingress`    | IP CIDR Blocks to Ingress to `baseca` ECS Service Service                                                                                                                             | list(string) | false    |         | ["10.0.0.1/24", "10.0.0.0.24"]                                                                   |
| `host_port`          | Port for `baseca` ECS Service Service                                                                                                                                                 | int          | true     | 9090    | 9090                                                                                             |
| `min_instance_count` | Minimum Instances for ECS Services                                                                                                                                                    | int          | true     | 1       | 2                                                                                                |
| `max_instance_count` | Maximum Instances for ECS Services                                                                                                                                                    | int          | true     | 2       | 4                                                                                                |
| `cpu`                | Maximum CPU for ECS Task                                                                                                                                                              | int          | true     | 2048    | [cpu](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html)    |
| `memory`             | Maximum Memory for ECS Task                                                                                                                                                           | int          | true     | 4096    | [memory](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html) |
| `baseca_iam_role`    | Task Role for `baseca` ECS Service                                                                                                                                                    | string       | false    |         | `module.baseca.baseca_iam_role`                                                                  |
| `ecr_repository`     | `baseca` ECR Repository URL                                                                                                                                                           | string       | false    |         | `module.baseca.ecr_repository`                                                                   |

Example Production Deployment for `production/baseca` Compute Module

```sh
# baseca/terraform/production/baseca.tf

module "compute" {
  source = "./compute"
  service = "baseca"
  region = "us-east-1"
  environment = "production"
  configuration = "production"

  vpc_id = "vpc-xxxxxxxx"
  subnet_ids = ["subnet-0123456789abcdef", "subnet-9876543210fedcba"]

  host_port = 9090
  network_ingress = ["10.0.0.0/8"]
  public_ip = false

  baseca_iam_role = module.baseca.baseca_iam_role
  ecr_repository = module.baseca.ecr_repository
  depends_on = [
    module.baseca
  ]
}
```
