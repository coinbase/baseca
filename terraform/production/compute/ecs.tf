resource "aws_ecs_cluster" "baseca" {
  name = "${var.service}-${var.environment}"
}

resource "aws_ecs_service" "baseca" {
  name            = "${var.service}-${var.environment}"
  cluster         = aws_ecs_cluster.baseca.id
  task_definition = aws_ecs_task_definition.baseca.arn
  desired_count   = var.min_instance_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.baseca.id]
    assign_public_ip = var.public_ip ? true : false
  }
  
  lifecycle {
    ignore_changes = [
      desired_count
    ]
  }
}

resource "aws_ecs_task_definition" "baseca" {
  family                = "${var.service}-${var.environment}"
  network_mode          = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu = var.cpu
  memory = var.memory
  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn = var.baseca_iam_role

  container_definitions = jsonencode([{
    name  = "baseca"
    image = "${var.ecr_repository}:latest"
    essential = true
    portMappings = [{
      containerPort = var.host_port
      hostPort      = var.host_port
      protocol      = "tcp"
    }]

    environment = [
      {
        "name": "ENVIRONMENT",
        "value": var.environment
      },
      {
        "name": "CONFIGURATION",
        "value": var.configuration
      }
    ]

    mountPoints = [{
      sourceVolume  = "efs"
      containerPath = "/tmp/baseca/ssl"
    }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group = var.service
        awslogs-region = var.region
        awslogs-stream-prefix = var.environment
      }
  }
  }])

  volume {
    name = "efs"

    efs_volume_configuration {
      file_system_id          = aws_efs_file_system.efs.id
      root_directory          = "/"
      transit_encryption      = "ENABLED"
      transit_encryption_port = 2049
      authorization_config {
        access_point_id = aws_efs_access_point.access_point.id
        iam             = "ENABLED"
      }
    }
  }
}

resource "aws_security_group" "baseca" {
  name        = "${var.service}-${var.environment}-compute"
  description = "baseca Instance Control Plane"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = var.host_port
    to_port     = var.host_port
    protocol    = "tcp"
    cidr_blocks = var.network_ingress
  }
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.network_ingress
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

    egress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = var.service
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "baseca" {
  name = var.service
  retention_in_days = 14
}
