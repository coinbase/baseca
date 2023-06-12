output "kinesis_firehose_stream" {
  description = "baseca Kinesis Firehose Delivery Stream"
    value = module.baseca.kinesis_firehose_stream
}

output "kms_key_id" {
  description = "baseca KMS Key for Signing User Auth Token"
  value = module.baseca.kms_key_id
}

output "rds_writer_endpoint" {
  description = "baseca RDS Writer Endpoint DNS Address"
  value = module.baseca.rds_writer_endpoint
}

output "rds_reader_endpoint" {
  description = "baseca RDS Reader Endpoint DNS Address"
  value = module.baseca.rds_reader_endpoint
}

output "redis_endpoint" {
  description = "baseca Elasticache Redis DNS Address"
  value = module.baseca.redis_endpoint
}

output "ecr_repository" {
  description = "baseca Elastic Container Registry (ECR) ARN"
  value = module.baseca.ecr_repository
}