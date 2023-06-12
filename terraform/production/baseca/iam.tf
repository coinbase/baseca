resource "aws_iam_role" "compute" {
  name = "${var.service}-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = ["ec2.amazonaws.com", "ecs-tasks.amazonaws.com"]
        }
      }
    ]
  })
}

resource "aws_iam_policy" "compute" {
  name        = "${var.service}-${var.environment}"
  description = "baseca Control Plane Permissions"
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "acm-pca:WaitUntilCertificateIssued",
          "acm-pca:GetCertificate",
          "acm-pca:GetCertificateAuthorityCertificate",
          "acm-pca:RevokeCertificate"
        ]
        Resource = var.acm_pca_arns
      },
      {
        Effect   = "Allow",
        Action   = "acm-pca:IssueCertificate",
        Resource = var.acm_pca_arns,
        Condition = {
          StringEquals = {
            "acm-pca:TemplateArn": [
              "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1",
              "arn:aws:acm-pca:::template/EndEntityClientAuthCertificate/V1",
              "arn:aws:acm-pca:::template/EndEntityServerAuthCertificate/V1",
              "arn:aws:acm-pca:::template/CodeSigningCertificate/V1"
            ]
          }
        }
      },
      {
        Effect   = "Allow",
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::*:role/baseca-node-attestation"
      },
      {
        Effect   = "Allow",
        Action   = [
          "firehose:PutRecord",
          "firehose:PutRecordBatch"
        ]
        Resource = aws_kinesis_firehose_delivery_stream.certificate_stream.arn
      },
      {
        Effect   = "Allow",
        Action   = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_rds_cluster.aurora_cluster.master_user_secret[0].secret_arn
      },
      {
        Effect   = "Allow",
        Action   = [
          "ec2:DescribeInstances",
          "iam:GetInstanceProfile"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "compute_policy_attachment" {
  policy_arn = aws_iam_policy.compute.arn
  role       = aws_iam_role.compute.name
}
