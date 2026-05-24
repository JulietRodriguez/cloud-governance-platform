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
        Action   = "s3:PutObject"
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
resource "aws_iam_policy" "s3_governance_policy" {
  name        = "s3-governance-policy"
  description = "Least privilege governance policy for S3 management"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.secure_bucket.arn,
          "${aws_s3_bucket.secure_bucket.arn}/*"
        ]
      }
    ]
  })

  tags = {
    Project     = "cloud-governance-platform"
    Environment = "dev"
    ManagedBy   = "Terraform"
    Governance  = "least-privilege"
  }
}
resource "aws_s3_bucket" "config_bucket" {
  bucket = "cloud-governance-config-jr-001"

  tags = {
    Project     = "cloud-governance-platform"
    Environment = "dev"
    ManagedBy   = "Terraform"
    Purpose     = "aws-config"
  }
}
resource "aws_iam_role" "config_role" {
  name = "aws-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"

        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
}
resource "aws_iam_role_policy_attachment" "config_policy_attach" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}
resource "aws_config_configuration_recorder" "config_recorder" {
  name     = "governance-config-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported = true
  }
}
resource "aws_config_delivery_channel" "config_delivery" {
  name           = "governance-config-delivery"
  s3_bucket_name = aws_s3_bucket.config_bucket.bucket

  depends_on = [
    aws_config_configuration_recorder.config_recorder
  ]
}
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name = "s3-bucket-public-read-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [
    aws_config_configuration_recorder.config_recorder
  ]
}
resource "aws_s3_bucket_policy" "config_bucket_policy" {
  bucket = aws_s3_bucket.config_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"

        Principal = {
          Service = "config.amazonaws.com"
        }

        Action = "s3:GetBucketAcl"

        Resource = aws_s3_bucket.config_bucket.arn
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"

        Principal = {
          Service = "config.amazonaws.com"
        }

        Action = "s3:PutObject"

        Resource = "${aws_s3_bucket.config_bucket.arn}/AWSLogs/719152986612/Config/*"

        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}