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
resource "aws_s3_bucket_public_access_block" "public_access" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "cloud-governance-cloudtrail-jr-001"

  tags = {
    Project     = "cloud-governance-platform"
    Environment = "dev"
    Owner       = "JulietRodriguez"
    ManagedBy   = "Terraform"
    Purpose     = "cloudtrail-logs"
  }
}
resource "aws_cloudtrail" "governance_trail" {
  name                          = "governance-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true

  tags = {
    Project     = "cloud-governance-platform"
    Environment = "dev"
    ManagedBy   = "Terraform"
  }
}
resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_bucket.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_bucket.arn}/AWSLogs/719152986612/*"

        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}