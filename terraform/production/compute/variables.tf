variable "service" {
  description = "Resource Prefix"
  type = string
  default = "baseca"
}

variable "environment" {
  description = "Service Environment"
  type = string
}

variable "region" {
  description = "AWS Region"
  type = string
}

variable "configuration" {
  description = "baseca Deployment Configuration"
  type = string
}

variable "vpc_id" {
  description = "AWS VPC ID"
  type = string
}

variable "public_ip" {
  description = "ECS Assign Public IP"
  type = bool
  default = false
}

variable "subnet_ids" {
  type = list(string)
}

variable "network_ingress" {
  description = "List of IP CIDR Blocks for Ingress to Service"
  type = list(string)
}

variable "host_port" {
  description = "EC2 Instance Service"
  type = number
  default = 9090
}

variable "lb_port" {
  description = "Application Load Balancer Port"
  type = number
  default = 9090
}

variable "min_instance_count" {
  description = "Minimum Instances in Target Group"
  type = number
  default = 1
}

variable "max_instance_count" {
  description = "Maximum Instance in Target Group"
  type = number
  default = 2
}

variable "cpu" {
  description = "CPU Allocated for ECS Service"
  type = number
  default = 2048
}

variable "memory" {
  description = "RAM Allocated for ECS Service"
  type = number
  default = 4096
}

variable "baseca_iam_role" {
  description = "baseca Control Plane IAM Role ARN"
  type = string
}

variable "ecr_repository" {
  description = "baseca ECR Registry ARN"
  type = string
}