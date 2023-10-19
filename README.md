[![Go Report Card](https://goreportcard.com/badge/github.com/coinbase/baseca)](https://goreportcard.com/report/github.com/coinbase/baseca) [![PR Build](https://github.com/coinbase/baseca/actions/workflows/pr_build.yml/badge.svg)](https://github.com/coinbase/baseca/actions/workflows/pr_build.yml) [![Release Build](https://github.com/coinbase/baseca/actions/workflows/release_build.yml/badge.svg)](https://github.com/coinbase/baseca/actions/workflows/release_build.yml)

<img src="docs/images/baseca.png" width="20%" height="20%" />

## Overview

`baseca` is a `gRPC` service that serves as a Public Key Infrastructure (PKI) control plane that issues short-lived x.509 certificates at runtime using attestation.

### Use Cases

`baseca` integrates with AWS Private CA and becomes as a management layer and a Certificate Authority; instead of issuing leaf certificates directly from Private CA, `baseca` issues and manages Subordinate Certificate Authorities from upstream used to sign requests depending on the [`scope`](docs/SCOPE.md) of a service account.

- Client Authentication
- Server Authentication
- Code Signing

<img src="docs/images/architecture.png" width="75%" height="75%" />

### Running `baseca`

- [`Architecture`](docs/ARCHITECTURE.md)
- [`Getting Started`](docs/GETTING_STARTED.md)
- [`Production Deployment`](docs/PRODUCTION_DEPLOYMENT.md)
- [`baseca gRPC Methods`](docs/ENDPOINTS.md)

### Benefits

- Short-Lived Certificates with Ephemeral Private Key Material
- No Limits on Number of Issued Certificates
- Protects Issuance of Certificates on Scope
- Supports Node Attestation
- Supports Issuance from On-Prem and Multi-Cloud
