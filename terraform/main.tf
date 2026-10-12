terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# VIOLATION: Missing server-side encryption configuration
resource "aws_s3_bucket" "failing_bucket" {
  bucket = "grc-audit-unencrypted-data-bucket"
}

# COMPLIANT: Server-side encryption explicit
resource "aws_s3_bucket" "passing_bucket" {
  bucket = "grc-audit-secure-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "passing_bucket_crypto" {
  bucket = aws_s3_bucket.passing_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}