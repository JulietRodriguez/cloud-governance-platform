# Customer managed key for the governed bucket, the CloudTrail bucket, the
# Config bucket, and CloudTrail log file encryption. Rotation is on.

resource "aws_kms_key" "governance" {
  description             = "cloud-governance-platform: S3 and CloudTrail encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.governance_key.json

  tags = {
    Project     = "cloud-governance-platform"
    Environment = "dev"
    ManagedBy   = "Terraform"
  }
}

resource "aws_kms_alias" "governance" {
  name          = "alias/cloud-governance-platform"
  target_key_id = aws_kms_key.governance.key_id
}

# In a key policy, "Resource": "*" means "this key". That is the documented
# form for key policies, not a wildcard over other resources.
data "aws_iam_policy_document" "governance_key" {
  # checkov:skip=CKV_AWS_109: Key policy; "*" refers to this key only, and the account root must administer it.
  # checkov:skip=CKV_AWS_111: Key policy; "*" refers to this key only.
  # checkov:skip=CKV_AWS_356: Key policy; "*" refers to this key only.
  statement {
    sid       = "EnableAccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowCloudTrailToEncryptLogs"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AllowCloudTrailToDescribeKey"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowConfigToWriteToEncryptedBucket"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}
