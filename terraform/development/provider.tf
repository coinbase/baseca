terraform {
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "3.4.3"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "5.1.0"
    }
  }
}
