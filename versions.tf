
terraform {
  # 1.3 is the floor for startswith() and lifecycle preconditions.
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}
