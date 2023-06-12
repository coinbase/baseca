resource "aws_kinesis_firehose_delivery_stream" "certificate_stream" {
  name        = "${var.service}-${var.environment}"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.certificate_stream.arn
    bucket_arn = aws_s3_bucket.certificate_metadata.arn
  }
}

resource "aws_s3_bucket" "certificate_metadata" {
  bucket = var.bucket
}

resource "aws_s3_bucket_policy" "certificate_stream" {
  bucket = aws_s3_bucket.certificate_metadata.id
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = aws_iam_role.certificate_stream.arn
        },
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ],
        Resource = [
          "${aws_s3_bucket.certificate_metadata.arn}",
          "${aws_s3_bucket.certificate_metadata.arn}/*"
        ],
        Condition = {
          "Bool": {
            "aws:SecureTransport": "true"
          }
        }
      }
    ]
  })
}

data "aws_iam_policy_document" "certificate_stream" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "certificate_stream" {
  name               = "${var.service}-${var.environment}-stream"
  assume_role_policy = data.aws_iam_policy_document.certificate_stream.json
}
