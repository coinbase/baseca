output "kinesis_firehose_stream" {
  description = "baseca Kinesis Firehose Delivery Stream"
    value = aws_kinesis_firehose_delivery_stream.certificate_stream.name
}

output "kms_key_id" {
  description = "baseca KMS Key for Signing User Auth Token"
  value = aws_kms_key.signing.key_id
} 