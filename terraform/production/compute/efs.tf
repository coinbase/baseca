resource "aws_efs_file_system" "efs" {
  creation_token = "${var.service}-${var.environment}"

  encrypted = true
  kms_key_id    = aws_kms_key.baseca_efs.arn

  tags = {
    Name = var.service
    Environment = var.environment
  }
}

resource "aws_efs_mount_target" "efs_mount_target" {
  count           = length(var.subnet_ids)
  file_system_id  = aws_efs_file_system.efs.id
  subnet_id       = var.subnet_ids[count.index]
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_access_point" "access_point" {
  file_system_id = aws_efs_file_system.efs.id

  posix_user {
    gid = 1000
    uid = 1000
  }

  root_directory {
    path = "/baseca"
    creation_info {
      owner_gid   = 1000
      owner_uid   = 1000
      permissions = "755"
    }
  }
}

resource "aws_efs_file_system_policy" "efs_policy" {
  file_system_id = aws_efs_file_system.efs.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = var.baseca_iam_role
        },
        Action = [
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientWrite"
        ],
        Resource = [
          "arn:aws:elasticfilesystem:${var.region}:${data.aws_caller_identity.account.account_id}:file-system/${aws_efs_file_system.efs.id}"
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

resource "aws_iam_policy" "efs_write_access" {
  name        = "${var.service}-${var.environment}-efs"
  description = "baseca Write Access to EFS"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "elasticfilesystem:ClientWrite",
          "elasticfilesystem:ClientMount"
        ],
        Resource = [
          "arn:aws:elasticfilesystem:${var.region}:${data.aws_caller_identity.account.account_id}:file-system/${aws_efs_file_system.efs.id}"
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

resource "aws_iam_role_policy_attachment" "baseca_efs" {
  role       = "${var.service}-${var.environment}"
  policy_arn = aws_iam_policy.efs_write_access.arn
}

resource "aws_security_group" "efs" {
  name        = "${var.service}-${var.environment}-efs"
  description = "baseca EFS Volume Security Group"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    security_groups = [aws_security_group.baseca.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_kms_key" "baseca_efs" {
  description = "baseca EFS Encryption Key"
}

data "aws_caller_identity" "account" {}
