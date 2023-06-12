resource "aws_kms_key" "signing" {
  customer_master_key_spec = var.key_spec
  description              = "Authentication Signing"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 10

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Principal = {
          AWS = aws_iam_role.compute.arn
        },
        Action = [
          "kms:DescribeKey",
          "kms:GetPublicKey",
          "kms:Verify",
          "kms:Sign"
        ],
        Resource = "*"
      },
      {
        Effect   = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.account.account_id}:root"
        },
        Action = "kms:*"
        Resource = "*"
      }      
    ]
  })

  tags = {
    Name = "${var.service}-${var.environment}"
  }
}

resource "aws_kms_alias" "baseca" {
  name          = "alias/${var.service}-${var.environment}"
  target_key_id = aws_kms_key.signing.key_id
}

data "aws_caller_identity" "account" {}
