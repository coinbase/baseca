<h3 align="center">
   coinbase/baseca
</h3>

## Overview

`baseca` is a `gRPC` service that serves as a Public Key Infrastructure (PKI) control plane intended to provide a safe and scalable approach to issue short-lived end-entities certificates.

### Use Cases

`baseca` extends the `pathlen` constraint from AWS Private CA and acts as an Intermediate CA; instead of issuing leaf certificates directly from Private CA, `baseca` manages many Subordinate CAs and signs requests in-memory depending on the [`scope`](docs/SCOPE.md) of the service account.

- Client Authentication
- Server Authentication
- Code Signing
- SSH Certificates (Pending)

### Running `baseca`

- [`Architecture`](docs/ARCHITECTURE.md)
- [`Getting Started`](docs/GETTING_STARTED.md)
- [`Production Deployment`](docs/PRODUCTION_DEPLOYMENT.md)
- [`baseca gRPC Methods`](docs/ENDPOINTS.md)

### Benefits

- Short-Lived Certificates with Ephemeral Private Key Material
- No Quotas on Quantity of Issued Certificates
- Supports Issuance from On-Prem and Multi-Cloud
- Protects Issuance of Certificates on Scope
- Supports Node Attestation
- Cost Savings
