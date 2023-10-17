# baseca RPC Methods

[`Certificate Endpoints`](#Certificate)

```protobuf
service Certificate {
  rpc SignCSR (CertificateSigningRequest) returns (SignedCertificate);
  rpc GetCertificate (CertificateSerialNumber) returns (CertificateParameter);
  rpc ListCertificates (ListCertificatesRequest) returns (CertificatesParameter);
  rpc RevokeCertificate (RevokeCertificateRequest) returns (RevokeCertificateResponse);
  rpc OperationsSignCSR (OperationsSignRequest) returns (SignedCertificate);
  rpc QueryCertificateMetadata (QueryCertificateMetadataRequest) returns (CertificatesParameter);
}
```

[`Service Endpoints`](#Service)

```protobuf
service Service {
  rpc CreateServiceAccount (CreateServiceAccountRequest) returns (CreateServiceAccountResponse);
  rpc CreateProvisionerAccount(CreateProvisionerAccountRequest) returns (CreateProvisionerAccountResponse);
  rpc GetProvisionerAccount (AccountId) returns (ProvisionerAccount);
  rpc GetServiceAccount (AccountId) returns (ServiceAccount);
  rpc GetServiceAccountMetadata (GetServiceAccountMetadataRequest) returns (ServiceAccounts);
  rpc DeleteServiceAccount (AccountId) returns (google.protobuf.Empty);
  rpc DeleteProvisionedServiceAccount (AccountId) returns (google.protobuf.Empty);
  rpc ProvisionServiceAccount (ProvisionServiceAccountRequest) returns (ProvisionServiceAccountResponse);
  rpc ListServiceAccounts (QueryParameter) returns (ServiceAccounts);
  rpc ListProvisionerAccounts (QueryParameter) returns (ProvisionerAccounts);
}
```

[`Account Endpoints`](#Account)

```protobuf
service Account {
  rpc LoginUser (LoginUserRequest) returns (LoginUserResponse);
  rpc DeleteUser (UsernameRequest) returns (google.protobuf.Empty);
  rpc GetUser (UsernameRequest) returns (User);
  rpc ListUsers (QueryParameter) returns (Users);
  rpc CreateUser (CreateUserRequest) returns (User);
  rpc UpdateUserCredentials (UpdateCredentialsRequest) returns (User);
  rpc UpdateUserPermissions (UpdatePermissionsRequest) returns (User);
}
```

## Certificate

### **baseca.v1.Certificate/SignCSR**

```protobuf
rpc SignCSR (CertificateSigningRequest) returns (SignedCertificate);
```

**Description**
Sign Certificate Signing Request (CSR)

**Authentication**
Service Account Authentication

**Client Example**
[sign_csr.go](../examples/certificate/baseca.v1.Certificate/sign_csr.go)

**Request**

```protobuf
message CertificateSigningRequest {
  string certificate_signing_request = 1;
}
```

**Response**

```protobuf
message SignedCertificate {
  string certificate = 1;
  string intermediate_certificate_chain = 2;
  string root_certificate_chain = 3;
  CertificateParameter metadata = 4;
}

message CertificateParameter {
  string serial_number = 1;
  string common_name = 2;
  repeated string subject_alternative_name = 3;
  google.protobuf.Timestamp expiration_date = 4;
  google.protobuf.Timestamp issued_date = 5;
  bool revoked = 6;
  string revoked_by = 7;
  google.protobuf.Timestamp revoke_date = 8;
  string ca_serial_number = 9;
  string certificate_authority_arn = 10;
}
```

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----",
  "intermediate_certificate_chain": "-----BEGIN CERTIFICATE-----",
  "root_certificate_chain": "-----BEGIN CERTIFICATE-----",
  "metadata": {
    "serial_number": "4c15b9ec07c2779f5319ab68ea16b7fc5f452f36",
    "common_name": "sandbox.example.com",
    "subject_alternative_name": ["test.example.com"],
    "expiration_date": {
      "seconds": 1685128356,
      "nanos": 876043203
    },
    "issued_date": {
      "seconds": 1682536356,
      "nanos": 876043115
    },
    "revoke_date": {
      "seconds": -62135596800
    },
    "ca_serial_number": "50919db8e90a157cb5d44f8b1eb87879",
    "certificate_authority_arn": "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/11111111-22222-3333-4444-555555555555"
  }
}
```

### **baseca.v1.Certificate/QueryCertificateMetadata**

```protobuf
rpc QueryCertificateMetadata (QueryCertificateMetadataRequest) returns (CertificatesParameter);
```

**Description**
Query for Non-Ephemeral Certificate Issued from Provisioner, Certificates Issued from `baseca.v1.Certificate/SignCSR` are Excluded

**Authentication**
Provisioner Account Authentication

**Request**

```protobuf
message QueryMetadataRequest {
  string serial_number = 1;
  string account = 2;
  string environment = 3;
  string extended_key = 4;
  repeated string subject_alternative_name = 5;
}
```

**Response**

```protobuf
message CertificatesParameter {
  repeated CertificateParameter certificates = 1;
}

message CertificateAuthorityParameter {
  string region = 1;
  string ca_arn = 2;
  string sign_algorithm = 3;
  bool assume_role = 4;
  string role_arn = 5;
  int32 validity = 6;
}
```

### **baseca.v1.Certificate/GetCertificate**

```protobuf
rpc GetCertificate (CertificateSerialNumber) returns (CertificateParameter);
```

**Description**
Query Issued Certificate Metadata from Database

**Authentication**
User Authentication

**Request**

```protobuf
message CertificateSerialNumber {
  string serial_number = 1;
}
```

```bash
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "serial_number": "4c15b9ec07c2779f5319ab68ea16b7fc5f452f36"
      }' \
  localhost:9090 baseca.v1.Certificate/GetCertificate
```

**Response**

```protobuf
message CertificateParameter {
  string serial_number = 1;
  string common_name = 2;
  repeated string subject_alternative_name = 3;
  google.protobuf.Timestamp expiration_date = 4;
  google.protobuf.Timestamp issued_date = 5;
  bool revoked = 6;
  string revoked_by = 7;
  google.protobuf.Timestamp revoke_date = 8;
  string ca_serial_number = 9;
  string certificate_authority_arn = 10;
}
```

```json
{
  "metadata": {
    "serial_number": "4c15b9ec07c2779f5319ab68ea16b7fc5f452f36",
    "common_name": "sandbox.example.com",
    "subject_alternative_name": ["test.example.com"],
    "expiration_date": "2023-09-25T03:30:11Z",
    "issued_date": "2023-08-25T03:30:11Z",
    "revoke_date": "0001-01-01T00:00:00Z",
    "ca_serial_number": "50919db8e90a157cb5d44f8b1eb87879",
    "certificate_authority_arn": "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/11111111-22222-3333-4444-555555555555"
  }
}
```

### **baseca.v1.Certificate/ListCertificates**

```protobuf
rpc ListCertificates (ListCertificatesRequest) returns (CertificatesParameter);
```

**Description**
List Issued Certificates via Common Name (CN)

**Authentication**
User Authentication

**Request**

```protobuf
message ListCertificatesRequest {
  string common_name = 1;
  int32 page_id = 3;
  int32 page_size = 4;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "common_name": "sandbox.example.com",
        "page_id": 1,
        "page_size": 20
      }' \
  localhost:9090 baseca.v1.Certificate/ListCertificates
```

**Response**

```protobuf
message CertificatesParameter {
  repeated CertificateParameter certificates = 1;
}
message CertificateAuthorityParameter {
  string region = 1;
  string ca_arn = 2;
  string sign_algorithm = 3;
  bool assume_role = 4;
  string role_arn = 5;
  int32 validity = 6;
}
```

### **baseca.v1.Certificate/RevokeCertificate**

```protobuf
rpc RevokeCertificate (RevokeCertificateRequest) returns (RevokeCertificateResponse);
```

**Description**
Revoke Subordinate CA Certificate from ACM Private CA

**Authentication**
User Authentication

**Request**

```protobuf
message RevokeCertificateRequest {
  string serial_number = 1;
  string revocation_reason = 2;
}
```

```
AFFILIATION_CHANGED
CESSATION_OF_OPERATION
A_A_COMPROMISE
PRIVILEGE_WITHDRAWN
SUPERSEDED
UNSPECIFIED
KEY_COMPROMISE
CERTIFICATE_AUTHORITY_COMPROMISE
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "serial_number": "50919db8e90a157cb5d44f8b1eb87879",
        "revocation_reason": "PRIVILEGE_WITHDRAWN"
      }' \
  localhost:9090 baseca.v1.Certificate/RevokeCertificate
```

**Response**

```protobuf
message RevokeCertificateResponse {
  string serial_number = 1;
  google.protobuf.Timestamp revocation_date = 2;
  string status = 3;
}
```

```json
{
  "serialNumber": "50919db8e90a157cb5d44f8b1eb87879",
  "revocationDate": "2023-04-26T21:49:59.846588Z",
  "status": "PRIVILEGE_WITHDRAWN"
}
```

### **baseca.v1.Certificate/OperationsSignCSR**

```protobuf
rpc OperationsSignCSR (OperationsSignRequest) returns (SignedCertificate);
```

**Description**
Manual Sign Certificate Signing Request (CSR)

**Authentication**
Provisioner Account Authentication

**Client Example**
[operations_sign_csr.go](../examples/certificate/baseca.v1.Certificate/operations_sign_csr.go)

**Request**

```protobuf
message OperationsSignRequest {
  string certificate_signing_request = 1;
  optional CertificateAuthorityParameter certificate_authority = 2;
  string service_account = 3;
  string environment = 4;
  string extended_key = 5;
}
```

**Response**

```protobuf
message SignedCertificate {
  string certificate = 1;
  string intermediate_certificate_chain = 2;
  string root_certificate_chain = 3;
  CertificateParameter metadata = 4;
}

message CertificateParameter {
  string serial_number = 1;
  string common_name = 2;
  repeated string subject_alternative_name = 3;
  google.protobuf.Timestamp expiration_date = 4;
  google.protobuf.Timestamp issued_date = 5;
  bool revoked = 6;
  string revoked_by = 7;
  google.protobuf.Timestamp revoke_date = 8;
  string certificate_authority_arn = 9;
  string account = 10;
  string environment = 11;
  string extended_key = 12;
```

## Service

### **baseca.v1.Service/CreateServiceAccount**

```protobuf
rpc CreateServiceAccount (CreateServiceAccountRequest) returns (CreateServiceAccountResponse);
```

**Description**
Create Service Account Record

**Authentication**
User Authentication

**Request**

```protobuf
message CreateServiceAccountRequest {
  string service_account = 1;
  string environment = 2;
  optional string regular_expression = 3;
  repeated string subject_alternative_names = 4;
  repeated string certificate_authorities = 5;
  string extended_key = 6;
  int32 certificate_validity = 7;
  string subordinate_ca = 8;
  optional NodeAttestation node_attestation = 9;
  string team = 10;
  string email = 11;

}

message NodeAttestation {
  AWSInstanceIdentityDocument aws_iid = 1;
}

message AWSInstanceIdentityDocument {
  string role_arn = 1;
  string assume_role = 2;
  repeated string security_groups = 3;
  string region = 4;
  string instance_id = 5;
  string image_id = 6;
  map<string, string> instance_tags = 7;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "service_account": "example",
        "environment": "development",
        "subject_alternative_names": [
          "development.coinbase.com"
        ],
        "extended_key": "EndEntityServerAuthCertificate",
        "node_attestation": {
          "aws_iid": {
            "role_arn": "arn:aws:iam::123456789012:instance-profile/instance-profile-name",
            "assume_role": "arn:aws:iam::123456789012:role/assumed-role",
            "security_groups": ["sg-0123456789abcdef0"],
            "region": "us-east-1"
          }
        },
        "certificate_authorities": [
          "development_use1"
        ],
        "certificate_validity": 30,
        "subordinate_ca": "infrastructure",
        "team": "Infrastructure Security",
        "email": "security@coinbase.com"
      }' \
  localhost:9090 baseca.v1.Service/CreateServiceAccount
```

**Response**

```protobuf
message CreateServiceAccountResponse {
  string client_id = 1;
  string client_token = 2;
  string service_account = 3;
  string environment = 4;
  string regular_expression = 5;
  repeated string subject_alternative_names = 6;
  repeated string certificate_authorities = 7;
  string extended_key = 8;
  NodeAttestation node_attestation = 9;
  int32 certificate_validity = 10;
  string subordinate_ca = 11;
  string team = 12;
  string email = 13;
  google.protobuf.Timestamp created_at = 14;
  string created_by = 15;
}
```

```json
{
  "clientId": "585c2f84-9a0e-4775-827a-a0a99c7dddcc",
  "clientToken": "[CLIENT_TOKEN]",
  "serviceAccount": "example",
  "environment": "development",
  "subjectAlternativeNames": ["development.coinbase.com"],
  "certificateAuthorities": ["development_use1"],
  "extendedKey": "EndEntityServerAuthCertificate",
  "nodeAttestation": {
    "awsIid": {
      "roleArn": "arn:aws:iam::123456789012:instance-profile/instance-profile-name",
      "assumeRole": "arn:aws:iam::123456789012:role/assumed-role",
      "securityGroups": ["sg-0123456789abcdef0"],
      "region": "us-east-1"
    }
  },
  "certificateValidity": 30,
  "subordinateCa": "infrastructure",
  "team": "Infrastructure Security",
  "email": "security@coinbase.com",
  "createdAt": "2023-04-26T22:24:42.873116Z",
  "createdBy": "830b9b81-37c0-4180-9dba-9f21b1f6ae21"
}
```

### **baseca.v1.Service/ListServiceAccounts**

```protobuf
rpc ListServiceAccounts (QueryParameter) returns (ServiceAccounts);
```

**Description**
Query Service Accounts from Database

**Authentication**
User Authentication

**Request**

```protobuf
message QueryParameter {
  int32 page_id = 2;
  int32 page_size = 3;
}
```

```sh
  grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "page_id": 1,
        "page_size": 20
      }' \
  localhost:9090 baseca.v1.Service/ListServiceAccounts
```

**Response**

```protobuf
message ServiceAccounts {
  repeated ServiceAccount service_accounts = 1;
}

message ServiceAccount {
  string client_id = 1;
  string service_account = 2;
  string environment = 3;
  string regular_expression = 4;
  repeated string subject_alternative_names = 5;
  repeated string certificate_authorities = 6;
  string extended_key = 7;
  NodeAttestation node_attestation = 8;
  int32 certificate_validity = 9;
  string subordinate_ca = 10;
  bool provisioned = 11;
  string team = 12;
  string email = 13;
  google.protobuf.Timestamp created_at = 14;
  string created_by = 15;
}
```

```json
{
  "serviceAccounts": [
    {
      "clientId": "585c2f84-9a0e-4775-827a-a0a99c7dddcc",
      "serviceAccount": "example",
      "environment": "development",
      "subjectAlternativeNames": ["development.coinbase.com"],
      "certificateAuthorities": ["development_use1"],
      "extendedKey": "EndEntityServerAuthCertificate",
      "nodeAttestation": {
        "awsIid": {
          "roleArn": "arn:aws:iam::123456789012:instance-profile/instance-profile-name",
          "assumeRole": "arn:aws:iam::123456789012:role/assumed-role",
          "securityGroups": ["sg-0123456789abcdef0"],
          "region": "us-east-1"
        }
      },
      "certificateValidity": 30,
      "subordinate_ca": "infrastructure",
      "provisioned": false,
      "team": "Infrastructure Security",
      "email": "security@coinbase.com",
      "createdAt": "2023-04-26T22:24:42.873116Z",
      "createdBy": "830b9b81-37c0-4180-9dba-9f21b1f6ae21"
    }
  ]
}
```

### **baseca.v1.Service/ListProvisionerAccounts**

```protobuf
rpc ListProvisionerAccounts (QueryParameter) returns (ProvisionerAccounts);
```

**Description**
List Provisioner Service Accounts

**Request**

```protobuf
message QueryParameter {
  int32 page_id = 2;
  int32 page_size = 3;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "page_id": 1,
        "page_size": 25
      }' \
  localhost:9090 baseca.v1.Service/ListProvisionerAccounts
```

**Response**

```protobuf
message ProvisionerAccounts {
  repeated ProvisionerAccount provisioner_accounts = 1;
}

message ProvisionerAccount {
  string client_id = 1;
  string provisioner_account = 2;
  repeated string environments = 3;
  string regular_expression = 4;
  repeated string subject_alternative_names = 5;
  repeated string extended_keys = 7;
  NodeAttestation node_attestation = 8;
  uint32 max_certificate_validity = 9;
  string team = 10;
  string email = 11;
  google.protobuf.Timestamp created_at = 12;
  string created_by = 13;
}

message NodeAttestation {
  AWSInstanceIdentityDocument aws_iid = 1;
}

message AWSInstanceIdentityDocument {
  string role_arn = 1;
  string assume_role = 2;
  repeated string security_groups = 3;
  string region = 4;
  string instance_id = 5;
  string image_id = 6;
  map<string, string> instance_tags = 7;
}
```

```json
{
  "provisionerAccounts": [
    {
      "clientId": "650b0ead-1c6b-49b3-810e-48d20a2890ac",
      "provisionerAccount": "example",
      "environments": ["development", "sandbox"],
      "regularExpression": "[A-Za-z0-9.-]",
      "subjectAlternativeNames": ["test.coinbase.com"],
      "extendedKeys": ["EndEntityServerAuthCertificate"],
      "nodeAttestation": {
        "awsIid": {
          "roleArn": "arn:aws:iam::123456789012:role/role",
          "assumeRole": "arn:aws:iam::123456789012:role/assumed-role",
          "securityGroups": ["sg-0123456789abcdef0"],
          "region": "us-east-1"
        }
      },
      "maxCertificateValidity": 30,
      "team": "Security",
      "email": "example@coinbase.com",
      "createdAt": "2023-04-26T22:24:42.873116Z",
      "createdBy": "830b9b81-37c0-4180-9dba-9f21b1f6ae21"
    }
  ]
}
```

### **baseca.v1.Service/GetServiceAccountMetadata**

```protobuf
rpc GetServiceAccountMetadata (GetServiceAccountMetadataRequest) returns (ServiceAccounts);
```

**Description**
Query Service Account from Database via Metadata

**Authentication**
User Authentication

**Request**

```protobuf
message GetServiceAccountMetadataRequest{
  string service_account = 1;
  string environment = 2;
  string extended_key = 3;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "service_account": "example",
        "environment": "development",
        "extended_key": "EndEntityServerAuthCertificate"
      }' \
  localhost:9090 baseca.v1.Service/GetServiceAccountMetadata
```

**Response**

```protobuf
message ServiceAccounts {
  repeated ServiceAccount service_accounts = 1;
}

message ServiceAccount {
  string client_id = 1;
  string service_account = 2;
  string environment = 3;
  string regular_expression = 4;
  repeated string subject_alternative_names = 5;
  repeated string certificate_authorities = 6;
  string extended_key = 7;
  NodeAttestation node_attestation = 8;
  int32 certificate_validity = 9;
  string subordinate_ca = 10;
  bool provisioned = 11;
  string team = 12;
  string email = 13;
  google.protobuf.Timestamp created_at = 14;
  string created_by = 15;
}
```

```json
{
  "serviceAccounts": [
    {
      "clientId": "585c2f84-9a0e-4775-827a-a0a99c7dddcc",
      "serviceAccount": "example",
      "environment": "development",
      "subjectAlternativeNames": ["development.coinbase.com"],
      "certificateAuthorities": ["development_use1"],
      "extendedKey": "EndEntityServerAuthCertificate",
      "nodeAttestation": {
        "awsIid": {
          "roleArn": "arn:aws:iam::123456789012:instance-profile/instance-profile-name",
          "assumeRole": "arn:aws:iam::123456789012:role/assumed-role",
          "securityGroups": ["sg-0123456789abcdef0"],
          "region": "us-east-1"
        }
      },
      "certificateValidity": 30,
      "subordinateCa": "infrastructure",
      "provisioned": false,
      "team": "Infrastructure Security",
      "email": "security@coinbase.com",
      "createdAt": "2023-04-26T22:24:42.873116Z",
      "createdBy": "830b9b81-37c0-4180-9dba-9f21b1f6ae21"
    }
  ]
}
```

### **baseca.v1.Service/GetServiceAccount**

```protobuf
rpc GetServiceAccount (AccountId) returns (ServiceAccount);
```

**Description**
Query Service Account from Database By UUID

**Authentication**
User Authentication

**Request**

```protobuf
message AccountId {
  string uuid = 1;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "uuid": "585c2f84-9a0e-4775-827a-a0a99c7dddcc"
      }' \
  localhost:9090 baseca.v1.Service/GetServiceAccount
```

**Response**

```protobuf
message ServiceAccount {
  string client_id = 1;
  string service_account = 2;
  string environment = 3;
  string regular_expression = 4;
  repeated string subject_alternative_names = 5;
  repeated string certificate_authorities = 6;
  string extended_key = 7;
  NodeAttestation node_attestation = 8;
  int32 certificate_validity = 9;
  string subordinate_ca = 10;
  bool provisioned = 11;
  string team = 12;
  string email = 13;
  google.protobuf.Timestamp created_at = 14;
  string created_by = 15;
}
```

```json
{
  "clientId": "585c2f84-9a0e-4775-827a-a0a99c7dddcc",
  "serviceAccount": "example",
  "environment": "development",
  "subjectAlternativeNames": ["development.coinbase.com"],
  "certificateAuthorities": ["development_use1"],
  "extendedKey": "EndEntityServerAuthCertificate",
  "nodeAttestation": {
    "awsIid": {
      "roleArn": "arn:aws:iam::123456789012:instance-profile/instance-profile-name",
      "assumeRole": "arn:aws:iam::123456789012:role/assumed-role",
      "securityGroups": ["sg-0123456789abcdef0"],
      "region": "us-east-1"
    }
  },
  "certificateValidity": 30,
  "subordinateCa": "infrastructure",
  "provisioned": false,
  "team": "Infrastructure Security",
  "email": "security@coinbase.com",
  "createdAt": "2023-04-26T22:24:42.873116Z",
  "createdBy": "830b9b81-37c0-4180-9dba-9f21b1f6ae21"
}
```

### **baseca.v1.Service/DeleteServiceAccount**

```protobuf
rpc DeleteServiceAccount (AccountId) returns (google.protobuf.Empty);
```

**Description**
Delete Service Account from Database

**Authentication**
User Authentication

**Request**

```protobuf
message AccountId {
  string uuid = 1;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "uuid": "585c2f84-9a0e-4775-827a-a0a99c7dddcc"
      }' \
  localhost:9090 baseca.v1.Service/DeleteServiceAccount
```

**Response**

```protobuf
google.protobuf.Empty
```

### **baseca.v1.Service/DeleteProvisionedServiceAccount**

```protobuf
rpc DeleteProvisionedServiceAccount (AccountId) returns (google.protobuf.Empty);
```

**Description**
Delete Service Account Generated from Provisioner

**Authentication**
Provisioner Account Authentication

**Request**

```protobuf
message AccountId {
  string uuid = 1;
}
```

**Response**

```protobuf
google.protobuf.Empty
```

### **baseca.v1.Service/CreateProvisionerAccount**

```protobuf
rpc CreateProvisionerAccount (CreateProvisionerAccountRequest) returns (CreateProvisionerAccountResponse);
```

**Description**
Create Provisioner Account Record

**Authentication**
User Authentication

**Request**

```protobuf
message CreateProvisionerAccountRequest {
  string provisioner_account = 1;
  repeated string environments = 2;
  optional string regular_expression = 3;
  repeated string subject_alternative_names = 4;
  repeated string extended_keys = 5;
  uint32 max_certificate_validity = 6;
  optional NodeAttestation node_attestation = 7;
  string team = 8;
  string email = 9;
}

message NodeAttestation {
  AWSInstanceIdentityDocument aws_iid = 1;
}

message AWSInstanceIdentityDocument {
  string role_arn = 1;
  string assume_role = 2;
  repeated string security_groups = 3;
  string region = 4;
  string instance_id = 5;
  string image_id = 6;
  map<string, string> instance_tags = 7;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "provisioner_account": "example",
        "environments": ["development"],
        "subject_alternative_names": [
          "development.coinbase.com"
        ],
        "extended_keys": ["EndEntityServerAuthCertificate"],
        "node_attestation": {
          "aws_iid": {
            "role_arn": "arn:aws:iam::123456789012:instance-profile/instance-profile-name",
            "assume_role": "arn:aws:iam::123456789012:role/assumed-role",
            "security_groups": ["sg-0123456789abcdef0"],
            "region": "us-east-1"
          }
        },
        "max_certificate_validity": 30,
        "team": "Infrastructure Security",
        "email": "security@coinbase.com"
      }' \
  localhost:9090 baseca.v1.Service/CreateProvisionerAccount
```

**Response**

```protobuf
message CreateProvisionerAccountResponse {
  string client_id = 1;
  string client_token = 2;
  string provisioner_account = 3;
  repeated string environments = 4;
  string regular_expression = 5;
  repeated string subject_alternative_names = 6;
  repeated string extended_keys = 8;
  NodeAttestation node_attestation = 9;
  uint32 max_certificate_validity = 10;
  string team = 11;
  string email = 12;
  google.protobuf.Timestamp created_at = 13;
  string created_by = 14;
}
```

```json
{
  "clientId": "585c2f84-9a0e-4775-827a-a0a99c7dddcc",
  "clientToken": "[CLIENT_TOKEN]",
  "provisionerAccount": "example",
  "environments": ["development"],
  "subjectAlternativeNames": ["development.coinbase.com"],
  "extendedKeys": ["EndEntityServerAuthCertificate"],
  "nodeAttestation": {
    "awsIid": {
      "roleArn": "arn:aws:iam::123456789012:instance-profile/instance-profile-name",
      "assumeRole": "arn:aws:iam::123456789012:role/assumed-role",
      "securityGroups": ["sg-0123456789abcdef0"],
      "region": "us-east-1"
    }
  },
  "maxCertificateValidity": 30,
  "team": "Infrastructure Security",
  "email": "security@coinbase.com",
  "createdAt": "2023-04-26T22:24:42.873116Z",
  "createdBy": "830b9b81-37c0-4180-9dba-9f21b1f6ae21"
}
```

### **baseca.v1.Service/GetProvisionerAccount**

```protobuf
rpc GetProvisionerAccount (AccountId) returns (ProvisionerAccount);
```

**Description**
Query Provisioner Account

**Authentication**
User Authentication

**Request**

```protobuf
message AccountId {
  string uuid = 1;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "uuid": "ce337d41-f8b5-4630-b469-5ef896cf4fc1"
      }' \
  localhost:9090 baseca.v1.Service/GetProvisionerAccount
```

**Response**

```protobuf
message ProvisionerAccount {
  string client_id = 1;
  string provisioner_account = 2;
  repeated string environments = 3;
  string regular_expression = 4;
  repeated string subject_alternative_names = 5;
  repeated string extended_keys = 7;
  NodeAttestation node_attestation = 8;
  uint32 max_certificate_validity = 9;
  string team = 10;
  string email = 11;
  google.protobuf.Timestamp created_at = 12;
  string created_by = 13;
}
```

```json
{
  "clientId": "585c2f84-9a0e-4775-827a-a0a99c7dddcc",
  "provisionerAccount": "example",
  "environments": ["development"],
  "subjectAlternativeNames": ["development.coinbase.com"],
  "extendedKeys": ["EndEntityServerAuthCertificate"],
  "nodeAttestation": {
    "awsIid": {
      "roleArn": "arn:aws:iam::123456789012:instance-profile/instance-profile-name",
      "assumeRole": "arn:aws:iam::123456789012:role/assumed-role",
      "securityGroups": ["sg-0123456789abcdef0"],
      "region": "us-east-1"
    }
  },
  "maxCertificateValidity": 30,
  "team": "Infrastructure Security",
  "email": "security@coinbase.com",
  "createdAt": "2023-04-26T22:24:42.873116Z",
  "createdBy": "830b9b81-37c0-4180-9dba-9f21b1f6ae21"
}
```

### **baseca.v1.Service/ProvisionServiceAccount**

```protobuf
rpc ProvisionServiceAccount (ProvisionServiceAccountRequest) returns (ProvisionServiceAccountResponse);
```

**Description**
Create Service Account Record

**Authentication**
Provisioner Account Authentication

**Request**

```protobuf
message ProvisionServiceAccountRequest {
  CreateServiceAccountRequest account = 1;
}

message CreateServiceAccountRequest {
  string service_account = 1;
  string environment = 2;
  optional string regular_expression = 3;
  repeated string subject_alternative_names = 4;
  repeated string certificate_authorities = 5;
  string extended_key = 6;
  int32 certificate_validity = 7;
  string subordinate_ca = 8;
  optional NodeAttestation node_attestation = 9;
  string team = 10;
  string email = 11;
  optional string region = 12;
}
message NodeAttestation {
  AWSInstanceIdentityDocument aws_iid = 1;
}
message AWSInstanceIdentityDocument {
  string role_arn = 1;
  string assume_role = 2;
  repeated string security_groups = 3;
  string region = 4;
  string instance_id = 5;
  string image_id = 6;
  map<string, string> instance_tags = 7;
}
```

**Response**

```protobuf
message ProvisionServiceAccountResponse {
  CreateServiceAccountResponse account = 1;
}
message CreateServiceAccountResponse {
  string client_id = 1;
  string client_token = 2;
  string service_account = 3;
  string environment = 4;
  string regular_expression = 5;
  repeated string subject_alternative_names = 6;
  repeated string certificate_authorities = 7;
  string extended_key = 8;
  NodeAttestation node_attestation = 9;
  int32 certificate_validity = 10;
  string subordinate_ca = 11;
  string team = 12;
  string email = 13;
  google.protobuf.Timestamp created_at = 14;
  string created_by = 15;
}
```

```json
{
  "account": {
    "clientId": "585c2f84-9a0e-4775-827a-a0a99c7dddcc",
    "clientToken": "[CLIENT_TOKEN]",
    "serviceAccount": "example",
    "environment": "development",
    "subjectAlternativeNames": ["development.coinbase.com"],
    "certificateAuthorities": ["sandbox_use1"],
    "extendedKey": "EndEntityServerAuthCertificate",
    "nodeAttestation": {
      "awsIid": {
        "roleArn": "arn:aws:iam::123456789012:instance-profile/instance-profile-name",
        "assumeRole": "arn:aws:iam::123456789012:role/assumed-role",
        "securityGroups": ["sg-0123456789abcdef0"],
        "region": "us-east-1"
      }
    },
    "certificateValidity": 30,
    "subordinateCa": "infrastructure",
    "team": "Infrastructure Security",
    "email": "security@coinbase.com",
    "createdAt": "2023-04-26T22:24:42.873116Z",
    "createdBy": "830b9b81-37c0-4180-9dba-9f21b1f6ae21"
  }
}
```

### **baseca.v1.Service/DeleteProvisionerAccount**

```protobuf
rpc DeleteProvisionerAccount (AccountId) returns (google.protobuf.Empty);
```

**Description**
Delete Provisioner Account from Database

**Authentication**
User Authentication

**Request**

```protobuf
message AccountId {
  string uuid = 1;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "uuid": "ce337d41-f8b5-4630-b469-5ef896cf4fc1"
      }' \
  localhost:9090 baseca.v1.Service/DeleteProvisionerAccount
```

**Response**

```protobuf
google.protobuf.Empty
```

## Account

### **baseca.v1.Account/LoginUser**

```protobuf
rpc LoginUser (LoginUserRequest) returns (LoginUserResponse);
```

**Description**
Returns JSON Web Token (JWT) for User Authentication Endpoints

**Authentication**
None

**Request**

```protobuf
message LoginUserRequest {
  string username = 1;
  string password = 2;
}
```

```sh
grpcurl -vv -plaintext \
  -d '{
    "username": "[USERNAME]",
    "password": "[PASSWORD]"
    }' \
  localhost:9090 baseca.v1.Account/LoginUser
```

**Response**

```protobuf
message LoginUserResponse {
  string access_token = 1;
  User user = 2;
}

message User {
  string uuid = 1;
  string username = 2;
  string full_name = 3;
  string email = 4;
  string permissions = 5;
  google.protobuf.Timestamp credential_changed_at = 6;
  google.protobuf.Timestamp created_at = 7;
}
```

```json
{
  "accessToken": "[JSON_WEB_TOKEN_OUTPUT]",
  "user": {
    "uuid": "585c2f84-9a0e-4775-827a-a0a99c7dddcc",
    "username": "security_operations",
    "fullName": "Example User",
    "email": "security@coinbase.com",
    "permissions": "ADMIN",
    "credentialChangedAt": "0001-01-01T00:00:00Z",
    "createdAt": "2023-02-28T07:21:04.221349Z"
  }
}
```

### **baseca.v1.Account/DeleteUser**

```protobuf
rpc DeleteUser (UsernameRequest) returns (google.protobuf.Empty);
```

**Description**
Delete User from Database

**Authentication**
User Authentication

**Request**

```protobuf
message UsernameRequest {
  string username = 1;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "username": "example@coinbase.com"
      }' \
  localhost:9090 baseca.v1.Account/DeleteUser
```

**Response**

```protobuf
google.protobuf.Empty
```

### **baseca.v1.Account/GetUser**

```protobuf
rpc GetUser (UsernameRequest) returns (User);
```

**Description**
Query User from Database

**Authentication**
User Authentication

**Request**

```protobuf
message UsernameRequest {
  string username = 1;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
    "username": "example@coinbase.com"
    }' \
    localhost:9090 baseca.v1.Account/GetUser
```

**Response**

```protobuf
message User {
  string uuid = 1;
  string username = 2;
  string full_name = 3;
  string email = 4;
  string permissions = 5;
  google.protobuf.Timestamp credential_changed_at = 6;
  google.protobuf.Timestamp created_at = 7;
}
```

```json
{
  "uuid": "585c2f84-9a0e-4775-827a-a0a99c7dddcc",
  "username": "example@coinbase.com",
  "fullName": "Example User",
  "email": "example@coinbase.com",
  "permissions": "ADMIN",
  "credentialChangedAt": "0001-01-01T00:00:00Z",
  "createdAt": "2023-04-06T05:31:03.960297Z"
}
```

### **baseca.v1.Account/ListUsers**

```protobuf
rpc ListUsers (QueryParameter) returns (Users);
```

**Description**
Query Users from Database

**Authentication**
User Authentication

**Request**

```protobuf
message QueryParameter {
  int32 page_id = 2;
  int32 page_size = 3;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "page_id": 1,
        "page_size": 20
      }' \
  localhost:9090 baseca.v1.Account/ListUsers
```

**Response**

```protobuf
message Users {
  repeated User users = 1;
}
message User {
  string uuid = 1;
  string username = 2;
  string full_name = 3;
  string email = 4;
  string permissions = 5;
  google.protobuf.Timestamp credential_changed_at = 6;
  google.protobuf.Timestamp created_at = 7;
}
```

```json
{
  "users": [
    {
      "uuid": "585c2f84-9a0e-4775-827a-a0a99c7dddcc",
      "username": "example@coinbase.com",
      "fullName": "Example User",
      "email": "example@coinbase.com",
      "permissions": "ADMIN",
      "credentialChangedAt": "0001-01-01T00:00:00Z",
      "createdAt": "2023-02-28T07:21:04.221349Z"
    },
    {
      "uuid": "bb8e9e1d-2a11-43ae-86f1-9a19b6c8f47e",
      "username": "sample@coinbase.com",
      "fullName": "Sample User",
      "email": "sample@coinbase.com",
      "permissions": "READ",
      "credentialChangedAt": "0001-01-01T00:00:00Z",
      "createdAt": "2023-03-28T05:58:07.822324Z"
    }
  ]
}
```

### **baseca.v1.Account/CreateUser**

```protobuf
rpc CreateUser (CreateUserRequest) returns (User);
```

**Description**
Create User to Manually Interface with baseca Control Plane

**Authentication**
User Authentication

**Request**

```protobuf
message CreateUserRequest {
  string username = 1;
  string password = 2;
  string full_name = 3;
  string email = 4;
  string permissions = 5;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "username": "example@coinbase.com",
        "password": "[PASSWORD]",
        "full_name": "Example User",
        "email": "example@coinbase.com",
        "permissions": "READ"
      }' \
  localhost:9090 baseca.v1.Account/CreateUser
```

**Response**

```protobuf
message User {
  string uuid = 1;
  string username = 2;
  string full_name = 3;
  string email = 4;
  string permissions = 5;
  google.protobuf.Timestamp credential_changed_at = 6;
  google.protobuf.Timestamp created_at = 7;
}
```

```json
{
  "uuid": "585c2f84-9a0e-4775-827a-a0a99c7dddcc",
  "username": "example@coinbase.com",
  "fullName": "Example User",
  "email": "example@coinbase.com",
  "permissions": "READ",
  "credentialChangedAt": "0001-01-01T00:00:00Z",
  "createdAt": "2023-04-27T00:38:22.776949Z"
}
```

### **baseca.v1.Account/UpdateUserCredentials**

```protobuf
rpc UpdateUserCredentials (UpdateCredentialsRequest) returns (User);
```

**Description**
Update User Password

**Authentication**
None

**Request**

```protobuf
message UpdateCredentialsRequest {
  string username = 1;
  string password = 2;
  string updated_password = 3;
}
```

```sh
grpcurl -vv -plaintext \
  -d '{
        "username": "example@coinbase.com",
        "password": "[PASSWORD]",
        "updated_password": "[UPDATED_PASSWORD]"
      }' \
  localhost:9090 baseca.v1.Account/UpdateUserCredentials
```

**Response**

```protobuf
message User {
  string uuid = 1;
  string username = 2;
  string full_name = 3;
  string email = 4;
  string permissions = 5;
  google.protobuf.Timestamp credential_changed_at = 6;
  google.protobuf.Timestamp created_at = 7;
}
```

### **baseca.v1.Account/UpdateUserPermissions**

```protobuf
rpc UpdateUserPermissions (UpdatePermissionsRequest) returns (User);
```

**Description**
Update Permissions Parameter for User

**Authentication**
User Authentication

**Request**

```protobuf
message UpdatePermissionsRequest {
  string username = 1;
  string permissions = 2;
}
```

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "username": "example@coinbase.com",
        "permissions": "ADMIN"
      }' \
  localhost:9090 baseca.v1.Account/UpdateUserPermissions
```

**Response**

```protobuf
message User {
  string uuid = 1;
  string username = 2;
  string full_name = 3;
  string email = 4;
  string permissions = 5;
  google.protobuf.Timestamp credential_changed_at = 6;
  google.protobuf.Timestamp created_at = 7;
}
```

```json
{
  "uuid": "585c2f84-9a0e-4775-827a-a0a99c7dddcc",
  "username": "example@coinbase.com",
  "fullName": "Example User",
  "email": "example@coinbase.com",
  "permissions": "ADMIN",
  "credentialChangedAt": "2023-06-04T01:17:48.919754Z",
  "createdAt": "2023-06-04T00:53:45.946512Z"
}
```
