###########################################################
# Terraform configuration
###########################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.73.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.1.0"
    }
  }
}

###########################################################
# Provider configuration
###########################################################

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = var.project_name
      Terraform   = "true"
    }
  }
}
