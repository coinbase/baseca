resource "aws_ecr_repository" "baseca" {
  name                 = "baseca"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}