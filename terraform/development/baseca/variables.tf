variable "service" {
  description = "Resource Prefix"
  type = string
  default = "baseca"
}

variable "environment" {
  description = "Service Environment"
  type = string
}

variable "region" {
  description = "AWS Region"
  type = string
}

variable "key_spec" {
  description = "KMS Key Spec: [SYMMETRIC_DEFAULT, RSA_2048, RSA_3072, RSA_4096, HMAC_256, ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521, ECC_SECG_P256K1]"
  type = string
  default = "RSA_4096"
}

variable "bucket" {
  description = "Bucket Name to Store Certificate Streaming Data from Firehose"
  type = string
}
