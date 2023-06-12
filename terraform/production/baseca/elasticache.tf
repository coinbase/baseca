resource "aws_elasticache_cluster" "baseca" {
  cluster_id           = "${var.service}-${var.environment}"
  engine               = "redis"
  node_type            = "cache.t3.small"
  num_cache_nodes      = 1
  parameter_group_name = aws_elasticache_parameter_group.baseca.name
  engine_version       = "6.2"
  port                 = 6379
  security_group_ids         = [aws_security_group.redis.id]

  snapshot_retention_limit = 7
  snapshot_window          = "05:00-09:00"
}

resource "aws_elasticache_parameter_group" "baseca" {
  name   = "${var.service}-${var.environment}-pg"
  family = "redis6.x"
}

resource "aws_security_group" "redis" {
  name        = "${var.service}-${var.environment}-redis"
  description = "baseca Redis Security Group"

  dynamic "ingress" {
    for_each = length(var.db_ingress_cidr) > 0 ? [1] : []
    content {
      from_port   = 6379
      to_port     = 6379
      protocol    = "tcp"
      cidr_blocks = var.db_ingress_cidr
    }
  }

  dynamic "ingress" {
    for_each = length(var.db_ingress_sg) > 0 ? [1] : []
    content {
      from_port       = 6379
      to_port         = 6379
      protocol        = "tcp"
      security_groups = var.db_ingress_sg
    }
  }

  tags = {
    Name = "${var.service}-${var.environment}-redis"
  }
}