variable "service" {
  description = "Resource Prefix"
  type = string
  default = "baseca"
}

variable "environment" {
  description = "Service Environment"
  type = string
}

variable "db_ingress_cidr" {
  description = "List of IP CIDR Blocks for Ingress to Database"
  type = list(string)
}

variable "db_ingress_sg" {
  description = "List of Security Groups for Ingress to Database"
  type = list(string)
  default = []
}

variable "db_subnet_ids" {
  description = "List of Subnets for RDS Database"
  type = list(string)
  default = []
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

variable "acm_pca_arns" {
  description = "List of Supported ACM Private CA ARNs"
  type    = list(string)
}

variable "vpc_id" {
  description = "AWS VPC ID"
  type = string
}