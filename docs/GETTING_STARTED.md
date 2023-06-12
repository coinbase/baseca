# Getting Started

`AWS` Dependencies:

- [Build Public Key Infrastructure](#public-key-infrastructure)
- [Create baseca Infrastructure](#build-infrastructure)

`baseca` Configuration:

- [baseca Service Configuration](CONFIGURATION.md)

`baseca` Database:

- [Run and Create Local Database Container](#1-run-and-create-local-database-container)

`baseca` gRPC Server:

- Option 1: [Build and Run baseca as Container](#3a-run-baseca-as-container-option-a)
- Option 2: [Compile baseca as Executable (amd64)](#3b-compile-baseca-as-executable-option-b)
- Option 3: [Run baseca as One-Off Execution](#3c-run-baseca-as-one-off-execution-option-c)

`Signing` x.509 Certificate:

- [Create Admin User](#2-create-initial-admin-user)
- [Create Service Account](#2-create-service-account)
- [Issue x.509 Certificate with `baseca` Client](#3-issue-x509-certificate-with-baseca-client)

## Public Key Infrastructure

Each organization will have different Public Key Infrastructure topologies depending on its needs; for your PKI to be compatible with `baseca` (a) Certificate Authorities must be AWS Private CA and (b) there must be a minimum [PathLen](https://docs.aws.amazon.com/privateca/latest/userguide/PcaTerms.html#terms-pathlength) depending on where `baseca` issues the Subordinate CA from. Designing a Public Key Infrastructure is out of scope of this document, but we will take a look at topologies that `baseca` is compatible with below:

- Option 1: Root CA (Self-Managed) &rarr; Intermediate CA (AWS): Minimum PathLen2 on Root CA, PathLen1 on Intermediate CA (Higher Complexity, Recommended)

- Option 2: Root CA (AWS) &rarr; Intermediate CA (AWS): Minimum PathLen2 on Root CA, PathLen1 on Intermediate CA (Lower Complexity, Recommended)

- Option 3: Root CA (AWS) &rarr; No AWS Intermediate CA: Minimum PathLen1 on Root CA (Not Recommended)

_PKI Architecture Example: Option 1_
<img src="images/public_key_infrastructure.png" width="100%" height="100%" />

## Build Infrastructure

### 1. Install Terraform

```sh
brew install tfenv
tfenv install 1.4.2
tfenv use 1.4.2
```

### 2. Configure Resource Module in `baseca/terraform/development`

`baseca` Infrastructure [Documentation](../terraform/README.md)

**NOTE:** Private CA(s) in `acm_pca_arns` must already exist within your infrastructure; refer to the [Public Key Infrastructure](#public-key-infrastructure) section if you need to design and deploy a Public Key Infrastructure.

**DISCLAIMER**: `DO NOT` use Private CA(s) that are used within your organization's `PRODUCTION` environment for this `GETTING_STARTED.md` document, this is meant to build a local development environment. For production deployments please refer to [`PRODUCTION_DEPLOYMENT.md`](PRODUCTION_DEPLOYMENT.md).

```sh
module "baseca" {
  source      = "./baseca"
  service     = "baseca"
  environment = "development"
  region      = "us-east-1"
  key_spec    = "RSA_4096"
  bucket      = "baseca-firehose-example"
}
```

### 3. Deploy Terraform Resource Module

```sh
cd /path/to/baseca/terraform/development

terraform init
terraform apply
```

### 4. Terraform Outputs

These outputs from Terraform will be utilized within the baseca `config.primary.local.sandbox.yml` configuration file.

```sh
terraform output

# Example Output

kinesis_firehose_stream = "baseca-development"
kms_key_id = "xxxxxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

## Configuration

Create and update the configuration [`config/config.primary.local.sandbox.yml`](../config/config.primary.local.sandbox.yml) file using the outputs created from the Terraform infrastructure; an example configuration can be seen within [CONFIGURATION.md](CONFIGURATION.md).

```yml
# Update config.primary.local.sandbox.yml
firehose:
  stream: baseca-development

kms:
  key_id: xxxxxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx # kms_key_id
```

| Variable                  | Description                                           | Update                       |
| ------------------------- | ----------------------------------------------------- | ---------------------------- |
| `grpc_server_address`     | gRPC Server Address and Port                          | No                           |
| `ocsp_server`             | Custom OCSP Server URL                                | Remove for Local Development |
| `database`                | baseca RDS Database                                   | No                           |
| `redis`                   | baseca Elasticache Redis Cluster                      | Remove for Local Development |
| `domains`                 | List of Valid Domains for `baseca` x.509 Certificates | Yes                          |
| `firehose`                | baseca Kinesis Data Firehose                          | Yes                          |
| `kms`                     | baseca Customer Managed KMS Key                       | Yes                          |
| `acm_pca`                 | AWS Private Certificate Authorities                   | Yes                          |
| `secrets_manager`         | AWS Secrets Manager                                   | Remove for Local Development |
| `subordinate_ca_metadata` | baseca Subordinate CA Attributes                      | Optional                     |
| `certificate_authority`   | Environment(s) for `acm_pca` Private CA(s)            | Yes                          |

## Local Deployment

### 1. Run and Create Local Database Container

Launch the PostgreSQL Container

```sh
# Start Postgres Database and Mount db/init to Container
docker run --name baseca -p 5432:5432  -v /path/to/baseca/db/init:/db/init -e POSTGRES_USER=root -e POSTGRES_PASSWORD=secret -d postgres:latest

# Create Initial baseca Database and Configure Root User Account
docker exec -it baseca createdb --username=root --owner=root baseca
```

[`golang-migrate Download Instructions`](https://github.com/golang-migrate/migrate/blob/master/cmd/migrate/README.md)

```sh
brew install golang-migrate # Darwin (MacOS)

migrate -path db/migration -database "postgresql://root:secret@localhost:5432/baseca?sslmode=disable" -verbose up
```

### 2. Create Initial Admin User

```sh
# Update db/init/init-docker.sql for Admin User
VALUES (uuid_generate_v4(), 'example@example.com', crypt('ADMIN_CREDENTIALS', gen_salt('bf')), 'Example User', 'example@example.com', 'ADMIN', now());

# Run Database Init to Create Admin User
docker exec -it baseca psql -U root -d baseca -a -f db/init/init-docker.sql
```

### 3a. Run baseca as Container (Option A)

_This step is recommended for production deployments using the standard Dockerfile that is provided for baseca._

Update the configuration file `config.primary.local.sandbox.yml`

```yml
# IPv4_ADDRESS (Darwin)
ifconfig en0 | grep inet

# Update config.primary.local.sandbox.yml
database_endpoint: IPv4_ADDRESS
database_reader_endpoint: IPv4_ADDRESS
ssl_mode: disable
```

Run the `baseca` Container

**NOTE:** You must have AWS credentials stored locally within `~/.aws` with permissions to all infrastructure components created from Terraform and access to the Private CAs.

```sh
docker run -p 9090:9090 -e password=secret -v ~/.aws/:/home/baseca/.aws/:ro -v $(pwd)/config:/home/baseca/config ghcr.io/coinbase/baseca:v0.0.1-alpha
```

### 3b. Compile `baseca` as Executable (Option B)

_This step is recommended for users that may want build the binary and then deploy their own custom container._

Update the configuration file `config.primary.local.sandbox.yml`

```yml
# Update config.primary.local.sandbox.yml
database_endpoint: localhost
database_reader_endpoint: localhost
ssl_mode: disable
```

Compile the Golang Binary `baseca`

```sh
# Darwin AMD64
GOOS=darwin GOARCH=amd64 go build -o target/bin/darwin/baseca cmd/server/main.go
password=secret ./target/bin/darwin/baseca

# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o target/bin/linux/baseca cmd/server/main.go
password=secret ./target/bin/linux/baseca
```

### 3c. Run baseca as One-Off Execution (Option C)

_This step is recommended for local testing and getting `baseca` running most quickly._

Update the configuration file `config.primary.local.sandbox.yml`

```yml
# Update config.primary.local.sandbox.yml
database_endpoint: localhost
database_reader_endpoint: localhost
ssl_mode: disable
```

Start the Golang `baseca` gRPC Server

```sh
password=secret go run cmd/server/main.go
```

## Signing x.509 Certificate

Start the `baseca` gRPC server via the preferred method within the [Local Deployment](#local-deployment) section and then run the [`baseca.v1.Account/LoginUser`](ENDPOINTS.md#basecav1accountloginuser) RPC method. 

### 1. Generate Authentication Token

Authenticate with the `ADMIN` user created from the [`Create Initial Admin User`](#2-create-initial-admin-user) section.

```sh
grpcurl -vv -plaintext \
  -d '{
    "username": "[USERNAME]",
    "password": "[PASSWORD]"
    }' \
  localhost:9090 baseca.v1.Account/LoginUser

# baseca.v1.Account/LoginUser Response
{
  "accessToken": "[AUTH_TOKEN]",
  "user": {
    "username": "example@coinbase.com",
    "fullName": "Example User",
    "email": "example@coinbase.com",
    "permissions": "ADMIN",
    "credentialChangedAt": "0001-01-01T00:00:00Z",
    "createdAt": "2023-05-01T12:00:00.000000Z"
  }
}

export AUTH_TOKEN=[AUTH_TOKEN]
```

### 2. Create Service Account

Build gRPC request to provision a service account; ensure that the environment and certificate authorities are mapped to the baseca configuration in `config/config.primary.local.sandbox.yml`.

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "service_account": "example",
        "environment": "development",
        "subject_alternative_names": [
          "development.coinbase.com"
        ],
        "extended_key": "EndEntityServerAuthCertificate",
        "certificate_authorities": [
          "development_use1"
        ],
        "certificate_validity": 30,
        "subordinate_ca": "infrastructure",
        "team": "Infrastructure Security",
        "email": "security@coinbase.com"
      }' \
  localhost:9090 baseca.v1.Service/CreateServiceAccount

# baseca.v1.Account/CreateServiceAccount Response

{
  "clientId": "585c2f84-9a0e-4775-827a-a0a99c7dddcc", # Service Account UUID
  "clientToken": "[CLIENT_TOKEN]", # Service Account Auth Token
  "serviceAccount": "example",
  "environment": "development",
  "subjectAlternativeNames": ["development.coinbase.com"],
  "certificateAuthorities": ["development_use1"],
  "extendedKey": "EndEntityServerAuthCertificate",
  "nodeAttestation": {}, # Node Attestation Not Applicable to Local Development
  "certificateValidity": 30,
  "subordinateCa": "infrastructure",
  "team": "Infrastructure Security",
  "email": "security@coinbase.com",
  "createdAt": "2023-05-01T12:00:00.000000Z",
  "createdBy": "830b9b81-37c0-4180-9dba-9f21b1f6ae21" # Admin User UUID
}
```

_Mapping Between `Service Account` and `baseca` Configuration_

<img src="images/configuration.png" width="100%" height="100%" />

### 3. Issue x.509 Certificate with `baseca` Client

After using the `baseca` client to issue a certificate the private key material and signed certificate will be stored within the parameters defined within `baseca.Output`. The private key material is generated locally, and because we are running the `baseca` server on our local machine the Subordinate CA will also be generated and written in memory under the `/tmp/baseca/ssl/[SUBORDINATE_CA]` directory.

```go
package main

import (
    "crypto/x509"
    "fmt"
    "log"

    baseca "github.com/coinbase/baseca/pkg/client"
)

func main() {
    client_id := [CLIENT_ID]
    client_token := [CLIENT_TOKEN]

    configuration := baseca.Configuration{
      URL:         "localhost:9090",
      Environment: baseca.Env.Local,
    }

    client, err := baseca.LoadDefaultConfiguration(configuration, client_id, client_token, baseca.Attestation.Local)

    if err != nil {
      // Handle Error
      log.Fatal(err)
    }

    metadata := baseca.CertificateRequest{
      CommonName:            "development.coinbase.com",
      SubjectAlternateNames: []string{"development.coinbase.com"},
      SigningAlgorithm:      x509.SHA512WithRSA,
      PublicKeyAlgorithm:    x509.RSA,
      KeySize:               4096,
      Output: baseca.Output{
        PrivateKey:                "/tmp/private.key", // baseca Generate Private Key Output Location
        Certificate:               "/tmp/certificate.crt", // baseca Signed Leaf Certificate Output Location
        CertificateChain:          "/tmp/full_chain.crt", // baseca Signed Certificate Chain Output Location
        CertificateSigningRequest: "/tmp/request.csr", // baseca CSR Output Location
      }
    }

    response, err := client.IssueCertificate(metadata)

    if err != nil {
      // Handle Error
      log.Fatal(err)
    }

  log.Printf("%+v", response)
}
```
