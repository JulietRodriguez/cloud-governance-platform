# AWS Config managed rules that check the controls this project deploys.
# Each rule maps to something in main.tf, kms.tf, or s3_hardening.tf, so a
# NON_COMPLIANT result means a deployed control has drifted.
# (s3-bucket-public-read-prohibited is in main.tf under its original address.)

locals {
  managed_config_rules = {
    # S3: matches the per-bucket hardening in s3_hardening.tf
    "s3-bucket-public-write-prohibited"        = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
    "s3-bucket-level-public-access-prohibited" = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
    "s3-bucket-server-side-encryption-enabled" = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
    "s3-bucket-versioning-enabled"             = "S3_BUCKET_VERSIONING_ENABLED"
    "s3-bucket-logging-enabled"                = "S3_BUCKET_LOGGING_ENABLED"
    "s3-bucket-ssl-requests-only"              = "S3_BUCKET_SSL_REQUESTS_ONLY"
    # CloudTrail: matches aws_cloudtrail.governance_trail
    "cloudtrail-enabled"                      = "CLOUD_TRAIL_ENABLED"
    "multi-region-cloudtrail-enabled"         = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
    "cloud-trail-log-file-validation-enabled" = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
    "cloud-trail-encryption-enabled"          = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
    # KMS: matches aws_kms_key.governance
    "cmk-backing-key-rotation-enabled" = "CMK_BACKING_KEY_ROTATION_ENABLED"
    # IAM: matches the least-privilege policy
    "iam-policy-no-statements-with-admin-access" = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }
}

resource "aws_config_config_rule" "managed" {
  for_each = local.managed_config_rules
  name     = each.key

  source {
    owner             = "AWS"
    source_identifier = each.value
  }

  depends_on = [aws_config_configuration_recorder.config_recorder]
}

# Tagging standard: every bucket must carry Project, Environment, Owner, ManagedBy.
resource "aws_config_config_rule" "required_tags_s3" {
  name = "required-tags-s3-buckets"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    tag1Key = "Project"
    tag2Key = "Environment"
    tag3Key = "Owner"
    tag4Key = "ManagedBy"
  })

  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }

  depends_on = [aws_config_configuration_recorder.config_recorder]
}
