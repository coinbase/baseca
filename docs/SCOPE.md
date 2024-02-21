# Scope

`Scope` is a concept for `service accounts` where attributes are defined to ensure that (a) the x.509 certificate issued should be unique to the service depending on the requirements, and (b) only the intended service is able to issue that x.509 certificate.

- **`Certificate Authorities`** define which Certificate Authority a service is able to issue from; this scope goes together with the environment constraint to ensure that a service is not able to have a certificate authorities that cross environments (i.e. development_use1, production_use1).

- **`Subject Alternative Names`** determine which Common Name (CN) and Subject Alternative Names (SAN) that are valid for the service account.

- **`Extended Key`** dictates the type of x.509 certificate that will be issued whether it will be used for client authentication (EndEntityClientAuthCertificate), server authentication (EndEntityServerAuthCertificate), or code signing (CodeSigningCertificate).

- **`Certificate Validity`** is a configurable value to determine when the expiration for an x.509 certificate will be; while we aim to have short-lived certificates for all of our services this is not always possible due to the nature of how often services are re-deployed.

- **`Node Attestation`** is used to ensure that the request is originating from the node we expect it; currently we support attestation from AWS Instance Identity Document (IID) which validates the signature of the request and maps it to ensure the request is coming from the intended server. In the case the service account credentials are compromised a certificate would not be issued unless the request is originating from the underlying node (i.e. EC2 instance).

- **`Subordinate CA`** is the and Subject Alternative Name (SAN) value of the Subordinate CA that will be issued from Private CA and used to sign requests downstream requests. For example, if the service account below made a request to baseca a Subordinate CA named `infrastructure_sandbox` would be created on the host and used to sign requests that also have a service account that uses the `infrastructure` subordinate_ca and is in the `sandbox` environment.

```sh
grpcurl -vv -plaintext -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
        "service_account": "example",
        "environment": "sandbox", # << Environment Scope >>
        "subject_alternative_names": [ # << Subject Alternative Names (SAN) Scope >>
          "sandbox.coinbase.com"
        ],
        "extended_key": "EndEntityServerAuthCertificate",
        "node_attestation": { # << Node Attestation Scope >>
          "aws_iid": {
            "role_arn": "arn:aws:iam::123456789012:instance-profile/instance-profile-name",
            "assume_role": "arn:aws:iam::123456789012:role/assumed-role",
            "security_groups": ["sg-0123456789abcdef0"],
            "region": "us-east-1"
          }
        },
        "certificate_authorities": [ # << Certificate Authorities Scope >>
          "sandbox_use1"
        ],
        "certificate_validity": 30, # << Certificate Validity Scope >>
        "subordinate_ca": "infrastructure", # << Subordinate CA Scope >>
        "team": "Infrastructure Security",
        "email": "security@coinbase.com"
      }' \
  localhost:9090 baseca.v1.Service/CreateServiceAccount
```

Using the service account issued above, if we generated a CSR and sent it to [`baseca.v1.Certificate/SignCSR`](ENDPOINTS.md#basecav1certificatesigncsr) the output for the leaf certificate would be similar to the one below.

```
-----BEGIN CERTIFICATE-----
MIIF4TCCA8mgAwIBAgIUYKMFt0fz3ajjsiQ6O1VT0XTGuUEwDQYJKoZIhvcNAQEN
BQAwczELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJh
bmNpc2NvMQswCQYDVQQKEwJDQTERMA8GA1UECxMIU2VjdXJpdHkxHzAdBgNVBAMM
FmluZnJhc3RydWN0dXJlX3NhbmRib3gwHhcNMjMwNTI0MjIxNTMzWhcNMjMwNjIz
MjIxNTMzWjB3MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xETAPBgNVBAoTCENvaW5iYXNlMREwDwYDVQQLEwhTZWN1cml0
eTEdMBsGA1UEAxMUc2FuZGJveC5jb2luYmFzZS5jb20wggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDLP6qvTSG+4qnfGCcY6ECEz4VBlaYI7cKjKarnxbUP
3RChJUsUUzDAohxol82LwBwN1zEkD2jtTFRnRN86DeTN9moQ2pDL4ePFm7tADnxc
wHd+xVBtvJjLQOKe5Oa21zGbRtfuXw/2nW1yeZPmVm3yhdOseoJjP2qEi8pnNyno
nP4mYvUYDHLJV5RY5IhjHkl6vQdenw9+9PiZUbLp1WGtgWYney9QhS5rGdy5IN5e
X3TVwKyUyNTApqt+dOgXsH8hOAyprgPB54bvjoH3q2oskJpHDD9QQtEtZ+8vod7v
vhdp62ywWrxLyjdE0Q+u5v8OyEXYKmVFzww2OSKVFPu6M5nj1SZvbYqZpfVnrYWz
RfEkJZ288tU0NKbOQEe0I4V5yMGT3DhFTE31h0CV7dop2qQpDZZCWtO5VusvL9p0
/6RCta9jOfsBBHAwx/UCrgB9tW5hP7CDYnjz6a8+awK4NMV7BU0JLOTt9EgCFUSg
3I7qQFc8IuAGbMX4RGpo0iCvWkOK/SCegAv96lwMT1WvgYlN+hNxAuM0mn0PDFvn
4K1RlNCQnys30i4qgJ0dIANhiO64VRHC8a6NGJy+h1uQ/Yq/YbLvGYctTkMIqGqq
D4CnhDfCntidtfcNqhhVJrH5pFE3OAtxi6IgSqjHijZ6NRTNIdXSr5/3vSXjAF8o
aQIDAQABo2kwZzAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
HwYDVR0jBBgwFoAUXq371v0v7mpEhQwZ5ZEl8ZXhSNgwHwYDVR0RBBgwFoIUc2Fu
ZGJveC5jb2luYmFzZS5jb20wDQYJKoZIhvcNAQENBQADggIBACdsEXqo7TLV0kDC
uCZgiNr0tdTrziKdex9vBJyxQCDJlDJRD2119kl4uZCP5B+uy1JTjOKDMCzzLkK8
Fi1STvIXOpQyO2zlAR0id3UuJGkJ+DpxFAqIHRCiPGTdxoqqggRI5Lo+PCVzE8Ya
p+lOsY9seqcS0hUxtowwSNL29VnuSEECNQ3yV3Z9moReWkjLHt+mOyBJVCNHRmxx
u3CO73g/WgkjAUpH2qZaURtNFtaEh3hnQ7wPs8A9UOSMbmI8brdo586IFAGfJlAr
hnVdoZO+5uOmNU1IhhRfXlHCX8MRuN06ci1MQ2LdqCvVmw1MdtE9HRBj3kj824E+
LyBZ1LP+hcz0LXfhU9lpLezRha+47d5TvseI9oijPvwdbwfPv2UfA2qQ9Wges1/o
y/LldJAzk6Wkk9vNrThBDRYCjWdoKxcROotWMYOzm+IZQOZ2+u+gV3WPO5U2r6mV
kxbVFaoLMA3485aXQBpnyFC/nqro6lf5SgtcTopFRCYQef+eVkuLsf+I7iMKObFE
t2dQy6vIXN1kHsAM9QKQDSKBYh3TjZi9KmY3e8gEFpXv0KzgOWS7JXCNZzZbegvL
XrHnWSowNC+VcpjTtLpI22cYFtYYPOlsSqgqYIS3VLecwdzBKsS/1qRQLvW4/pXN
jqXtvcRCofiEWOkOxBlz1JJvHV/N
-----END CERTIFICATE-----
```

Taking a further look, we can decode the certificate with `openssl x509 -in [file].crt -noout -text` which we can then correlate to the scopes that were defined within the service account.

- x.509 Server Certificate
- Signed by Subordinate CA Generated from `sandbox_use1`
- Common Name (CN) and Subject Alternative Names (SAN) of `sandbox.coinbase.com`
- Certificate Validity of `30 Days`
- Request Must Come from EC2 with Attributes within `aws_iid`

```sh
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            60:a3:05:b7:47:f3:dd:a8:e3:b2:24:3a:3b:55:53:d1:74:c6:b9:41
    Signature Algorithm: sha512WithRSAEncryption # Signing Algorithm (Configurable in baseca Client)
        Issuer: C=US, ST=CA, L=San Francisco, O=CA, OU=Security, CN=infrastructure_sandbox # Subordinate CA Issued by baseca
        Validity
            Not Before: May 24 22:15:33 2023 GMT
            Not After : Jun 23 22:15:33 2023 GMT # Certificate Validity
        Subject: C=US, ST=CA, L=San Francisco, O=Coinbase, OU=Security, CN=sandbox.coinbase.com # Common Name (CN)
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption # Key Algorithm (Configurable in baseca Client)
                RSA Public-Key: (4096 bit) # Key Size (Configurable in baseca Client)
                Modulus:
                    00:cb:3f:aa:af:4d:21:be:e2:a9:df:18:27:18:e8:
                    40:84:cf:85:41:95:a6:08:ed:c2:a3:29:aa:e7:c5:
                    b5:0f:dd:10:a1:25:4b:14:53:30:c0:a2:1c:68:97:
                    cd:8b:c0:1c:0d:d7:31:24:0f:68:ed:4c:54:67:44:
                    df:3a:0d:e4:cd:f6:6a:10:da:90:cb:e1:e3:c5:9b:
                    bb:40:0e:7c:5c:c0:77:7e:c5:50:6d:bc:98:cb:40:
                    e2:9e:e4:e6:b6:d7:31:9b:46:d7:ee:5f:0f:f6:9d:
                    6d:72:79:93:e6:56:6d:f2:85:d3:ac:7a:82:63:3f:
                    6a:84:8b:ca:67:37:29:e8:9c:fe:26:62:f5:18:0c:
                    72:c9:57:94:58:e4:88:63:1e:49:7a:bd:07:5e:9f:
                    0f:7e:f4:f8:99:51:b2:e9:d5:61:ad:81:66:27:7b:
                    2f:50:85:2e:6b:19:dc:b9:20:de:5e:5f:74:d5:c0:
                    ac:94:c8:d4:c0:a6:ab:7e:74:e8:17:b0:7f:21:38:
                    0c:a9:ae:03:c1:e7:86:ef:8e:81:f7:ab:6a:2c:90:
                    9a:47:0c:3f:50:42:d1:2d:67:ef:2f:a1:de:ef:be:
                    17:69:eb:6c:b0:5a:bc:4b:ca:37:44:d1:0f:ae:e6:
                    ff:0e:c8:45:d8:2a:65:45:cf:0c:36:39:22:95:14:
                    fb:ba:33:99:e3:d5:26:6f:6d:8a:99:a5:f5:67:ad:
                    85:b3:45:f1:24:25:9d:bc:f2:d5:34:34:a6:ce:40:
                    47:b4:23:85:79:c8:c1:93:dc:38:45:4c:4d:f5:87:
                    40:95:ed:da:29:da:a4:29:0d:96:42:5a:d3:b9:56:
                    eb:2f:2f:da:74:ff:a4:42:b5:af:63:39:fb:01:04:
                    70:30:c7:f5:02:ae:00:7d:b5:6e:61:3f:b0:83:62:
                    78:f3:e9:af:3e:6b:02:b8:34:c5:7b:05:4d:09:2c:
                    e4:ed:f4:48:02:15:44:a0:dc:8e:ea:40:57:3c:22:
                    e0:06:6c:c5:f8:44:6a:68:d2:20:af:5a:43:8a:fd:
                    20:9e:80:0b:fd:ea:5c:0c:4f:55:af:81:89:4d:fa:
                    13:71:02:e3:34:9a:7d:0f:0c:5b:e7:e0:ad:51:94:
                    d0:90:9f:2b:37:d2:2e:2a:80:9d:1d:20:03:61:88:
                    ee:b8:55:11:c2:f1:ae:8d:18:9c:be:87:5b:90:fd:
                    8a:bf:61:b2:ef:19:87:2d:4e:43:08:a8:6a:aa:0f:
                    80:a7:84:37:c2:9e:d8:9d:b5:f7:0d:aa:18:55:26:
                    b1:f9:a4:51:37:38:0b:71:8b:a2:20:4a:a8:c7:8a:
                    36:7a:35:14:cd:21:d5:d2:af:9f:f7:bd:25:e3:00:
                    5f:28:69
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication # Extended Key
            X509v3 Authority Key Identifier:
                keyid:5E:AD:FB:D6:FD:2F:EE:6A:44:85:0C:19:E5:91:25:F1:95:E1:48:D8

            X509v3 Subject Alternative Name:
                DNS:sandbox.coinbase.com # Subject Alternative Name (SAN)
    Signature Algorithm: sha512WithRSAEncryption
         27:6c:11:7a:a8:ed:32:d5:d2:40:c2:b8:26:60:88:da:f4:b5:
         d4:eb:ce:22:9d:7b:1f:6f:04:9c:b1:40:20:c9:94:32:51:0f:
         6d:75:f6:49:78:b9:90:8f:e4:1f:ae:cb:52:53:8c:e2:83:30:
         2c:f3:2e:42:bc:16:2d:52:4e:f2:17:3a:94:32:3b:6c:e5:01:
         1d:22:77:75:2e:24:69:09:f8:3a:71:14:0a:88:1d:10:a2:3c:
         64:dd:c6:8a:aa:82:04:48:e4:ba:3e:3c:25:73:13:c6:1a:a7:
         e9:4e:b1:8f:6c:7a:a7:12:d2:15:31:b6:8c:30:48:d2:f6:f5:
         59:ee:48:41:02:35:0d:f2:57:76:7d:9a:84:5e:5a:48:cb:1e:
         df:a6:3b:20:49:54:23:47:46:6c:71:bb:70:8e:ef:78:3f:5a:
         09:23:01:4a:47:da:a6:5a:51:1b:4d:16:d6:84:87:78:67:43:
         bc:0f:b3:c0:3d:50:e4:8c:6e:62:3c:6e:b7:68:e7:ce:88:14:
         01:9f:26:50:2b:86:75:5d:a1:93:be:e6:e3:a6:35:4d:48:86:
         14:5f:5e:51:c2:5f:c3:11:b8:dd:3a:72:2d:4c:43:62:dd:a8:
         2b:d5:9b:0d:4c:76:d1:3d:1d:10:63:de:48:fc:db:81:3e:2f:
         20:59:d4:b3:fe:85:cc:f4:2d:77:e1:53:d9:69:2d:ec:d1:85:
         af:b8:ed:de:53:be:c7:88:f6:88:a3:3e:fc:1d:6f:07:cf:bf:
         65:1f:03:6a:90:f5:68:1e:b3:5f:e8:cb:f2:e5:74:90:33:93:
         a5:a4:93:db:cd:ad:38:41:0d:16:02:8d:67:68:2b:17:11:3a:
         8b:56:31:83:b3:9b:e2:19:40:e6:76:fa:ef:a0:57:75:8f:3b:
         95:36:af:a9:95:93:16:d5:15:aa:0b:30:0d:f8:f3:96:97:40:
         1a:67:c8:50:bf:9e:aa:e8:ea:57:f9:4a:0b:5c:4e:8a:45:44:
         26:10:79:ff:9e:56:4b:8b:b1:ff:88:ee:23:0a:39:b1:44:b7:
         67:50:cb:ab:c8:5c:dd:64:1e:c0:0c:f5:02:90:0d:22:81:62:
         1d:d3:8d:98:bd:2a:66:37:7b:c8:04:16:95:ef:d0:ac:e0:39:
         64:bb:25:70:8d:67:36:5b:7a:0b:cb:5e:b1:e7:59:2a:30:34:
         2f:95:72:98:d3:b4:ba:48:db:67:18:16:d6:18:3c:e9:6c:4a:
         a8:2a:60:84:b7:54:b7:9c:c1:dc:c1:2a:c4:bf:d6:a4:50:2e:
         f5:b8:fe:95:cd:8e:a5:ed:bd:c4:42:a1:f8:84:58:e9:0e:c4:
         19:73:d4:92:6f:1d:5f:cd
```
