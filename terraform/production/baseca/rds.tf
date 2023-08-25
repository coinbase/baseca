resource "aws_rds_cluster" "aurora_cluster" {
  cluster_identifier      = "${var.service}-${var.environment}-cluster"
  engine                  = "aurora-postgresql"
  engine_version          = "14"
  backup_retention_period = 3
  skip_final_snapshot     = true
  apply_immediately       = true
  storage_encrypted       = true
  vpc_security_group_ids  = [aws_security_group.baseca.id]
  db_subnet_group_name    = aws_db_subnet_group.baseca.name

  database_name = "baseca"
  master_username = "baseca"
  manage_master_user_password = true
}

resource "aws_rds_cluster_instance" "cluster_instances" {
  count              = 2
  identifier         = "aurora-cluster-instance-${var.service}-${count.index}"
  cluster_identifier = aws_rds_cluster.aurora_cluster.id
  instance_class     = "db.t4g.medium"
  engine             = "aurora-postgresql"
  engine_version     = "14"
  auto_minor_version_upgrade = true
  publicly_accessible = false
}

resource "aws_security_group" "baseca" {
  name        = "${var.service}-${var.environment}-db"
  description = "baseca Database Security Group"
  vpc_id = var.vpc_id

  dynamic "ingress" {
    for_each = length(var.db_ingress_cidr) > 0 ? [1] : []
    content {
      from_port   = 5432
      to_port     = 5432
      protocol    = "tcp"
      cidr_blocks = var.db_ingress_cidr
    }
  }

  dynamic "ingress" {
    for_each = length(var.db_ingress_sg) > 0 ? [1] : []
    content {
      from_port       = 5432
      to_port         = 5432
      protocol        = "tcp"
      security_groups = var.db_ingress_sg
    }
  }

  tags = {
    Name = "${var.service}-${var.environment}-db"
  }
}

resource "aws_db_subnet_group" "baseca" {
  name       = "${var.service}-${var.environment}"
  subnet_ids = var.db_subnet_ids

  tags = {
    Name = "${var.service}-${var.environment}"
  }
}