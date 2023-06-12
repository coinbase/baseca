output "kinesis_firehose_stream" {
  description = "baseca Kinesis Firehose Delivery Stream"
    value = module.baseca.kinesis_firehose_stream
}

output "kms_key_id" {
  description = "baseca KMS Key for Signing User Auth Token"
  value = module.baseca.kms_key_id
}
