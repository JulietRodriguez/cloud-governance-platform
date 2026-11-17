locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.name
  trail_name = "governance-trail"
  trail_arn  = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

# ---------------------------------------------------------------------------
# S3 buckets
#   secure_bucket      governed data bucket
#   log_bucket         S3 server access logs for the other three buckets
#   cloudtrail_bucket  CloudTrail log files
#   config_bucket      AWS Config snapshots and history
# Hardening for every bucket (encryption, versioning, public access block,
# TLS-only policy, access logging, lifecycle) is in s3_hardening.tf.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "secure_bucket" {
  # checkov:skip=CKV_AWS_144: Single-region demo environment; cross-region replication not required.
  # checkov:skip=CKV2_AWS_62: No downstream consumer for object events in this demo.
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
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.governance.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "public_access" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Access logs can only be delivered to a bucket encrypted with SSE-S3, so this
# bucket uses AES256 instead of the customer managed key (see s3_hardening.tf).
#tfsec:ignore:aws-s3-enable-bucket-logging
resource "aws_s3_bucket" "log_bucket" {
  # checkov:skip=CKV_AWS_18: This is the access-log target bucket; logging it to itself would create a loop.
  # checkov:skip=CKV_AWS_144: Single-region demo environment; cross-region replication not required.
  # checkov:skip=CKV2_AWS_62: Event notifications not needed for a log archive bucket.
  # checkov:skip=CKV_AWS_145: S3 server access logs can only be delivered to SSE-S3 (AES256) buckets, not SSE-KMS.
  bucket = "cloud-governance-platform-logs-jr-001"

  tags = {
    Project     = "cloud-governance-platform"
    Environment = "dev"
    Owner       = "JulietRodriguez"
    ManagedBy   = "Terraform"
    Purpose     = "access-logs"
  }
}

resource "aws_s3_bucket" "cloudtrail_bucket" {
  # checkov:skip=CKV_AWS_144: Single-region demo environment; cross-region replication not required.
  # checkov:skip=CKV2_AWS_62: Event notifications not needed for a log archive bucket.
  bucket = "cloud-governance-cloudtrail-jr-001"

  tags = {
    Project     = "cloud-governance-platform"
    Environment = "dev"
    Owner       = "JulietRodriguez"
    ManagedBy   = "Terraform"
    Purpose     = "cloudtrail-logs"
  }
}

resource "aws_s3_bucket" "config_bucket" {
  # checkov:skip=CKV_AWS_144: Single-region demo environment; cross-region replication not required.
  # checkov:skip=CKV2_AWS_62: Event notifications not needed for a log archive bucket.
  bucket = "cloud-governance-config-jr-001"

  tags = {
    Project     = "cloud-governance-platform"
    Environment = "dev"
    Owner       = "JulietRodriguez"
    ManagedBy   = "Terraform"
    Purpose     = "aws-config"
  }
}

# ---------------------------------------------------------------------------
# CloudTrail: multi-region, log file validation, encrypted with the CMK
# ---------------------------------------------------------------------------

#tfsec:ignore:aws-cloudtrail-ensure-cloudwatch-integration
resource "aws_cloudtrail" "governance_trail" {
  # checkov:skip=CKV2_AWS_10: Logs go to an encrypted, versioned S3 bucket; CloudWatch Logs delivery is left out to keep the demo low-cost.
  # checkov:skip=CKV_AWS_252: No SNS notification topic is needed for this demo trail.
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.governance.arn

  tags = {
    Project     = "cloud-governance-platform"
    Environment = "dev"
    ManagedBy   = "Terraform"
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_policy]
}

resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_bucket.arn
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_bucket.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.trail_arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.cloudtrail_bucket.arn, "${aws_s3_bucket.cloudtrail_bucket.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# IAM: least-privilege policy for the governed bucket
# ---------------------------------------------------------------------------

# Object-level access needs "<bucket>/*": the wildcard covers objects in this
# one bucket only, which is the least-privilege form for GetObject/PutObject.
#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_policy" "s3_governance_policy" {
  name        = "s3-governance-policy"
  description = "Least privilege governance policy for S3 management"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListGovernedBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [aws_s3_bucket.secure_bucket.arn]
      },
      {
        Sid      = "ReadWriteGovernedObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = ["${aws_s3_bucket.secure_bucket.arn}/*"]
      },
      {
        Sid      = "UseGovernanceKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [aws_kms_key.governance.arn]
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

# ---------------------------------------------------------------------------
# AWS Config: recorder, delivery channel, recorder status (managed rules are
# in config_rules.tf)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "config_role" {
  name = "aws-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config_policy_attach" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "config_recorder" {
  name     = "governance-config-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "config_delivery" {
  name           = "governance-config-delivery"
  s3_bucket_name = aws_s3_bucket.config_bucket.bucket

  depends_on = [
    aws_config_configuration_recorder.config_recorder,
    aws_s3_bucket_policy.config_bucket_policy,
  ]
}

# Without this resource Terraform creates the recorder but leaves it stopped.
resource "aws_config_configuration_recorder_status" "config_recorder_status" {
  name       = aws_config_configuration_recorder.config_recorder.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.config_delivery]
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
        Sid       = "AWSConfigBucketPermissionsCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.config_bucket.arn
        Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
      },
      {
        Sid       = "AWSConfigBucketExistenceCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.config_bucket.arn
        Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
      },
      {
        Sid       = "AWSConfigBucketDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config_bucket.arn}/AWSLogs/${local.account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = local.account_id
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.config_bucket.arn, "${aws_s3_bucket.config_bucket.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}
