output "kinesis_firehose_stream" {
  description = "baseca Kinesis Firehose Delivery Stream"
    value = aws_kinesis_firehose_delivery_stream.certificate_stream.name
}

output "kms_key_id" {
  description = "baseca KMS Key for Signing User Auth Token"
  value = aws_kms_key.signing.key_id
} 

output "rds_writer_endpoint" {
  description = "baseca RDS Writer Endpoint DNS Address"
  value = aws_rds_cluster.aurora_cluster.endpoint
}

output "rds_reader_endpoint" {
  description = "baseca RDS Reader Endpoint DNS Address"
  value = aws_rds_cluster.aurora_cluster.reader_endpoint
}

output "redis_endpoint" {
  description = "baseca Elasticache Redis DNS Address"
  value = aws_elasticache_cluster.baseca.cache_nodes.0.address
}

output "baseca_iam_role" {
  description = "baseca Control Plane IAM Role ARN"
  value = aws_iam_role.compute.arn
}

output "ecr_repository" {
  description = "baseca Elastic Container Registry (ECR) ARN"
  value = aws_ecr_repository.baseca.repository_url
}
