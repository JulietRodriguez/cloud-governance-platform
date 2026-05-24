resource "aws_s3_bucket" "secure_bucket" {
  bucket = "cloud-governance-platform-jr-001"

  tags = {
    Project     = "cloud-governance-platform"
    Environment = "dev"
    Owner       = "JulietRodriguez"
    ManagedBy   = "Terraform"
    Compliance  = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.secure_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "cloud-governance-platform-logs-jr-001"

  tags = {
    Project     = "cloud-governance-platform"
    Environment = "dev"
    Owner       = "JulietRodriguez"
    ManagedBy   = "Terraform"
    Purpose     = "access-logs"
  }
}



