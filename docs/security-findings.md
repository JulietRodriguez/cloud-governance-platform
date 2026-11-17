# Security Findings Review

## Summary

The pipeline runs **tfsec**, **Checkov**, and **OPA/Conftest**, and all three block the merge.

Before this change, tfsec ran with `continue-on-error: true`, so its findings never failed the build. On that version of the Terraform it reported **33 findings**:

| Severity | Count |
|---|---|
| High | 22 |
| Medium | 7 |
| Low | 4 |

Most came from three of the four S3 buckets (log, CloudTrail, Config) having no encryption, versioning, or public access block. Others were unencrypted CloudTrail logs without log file validation, and an IAM statement that mixed bucket-level and object-level actions.

All were fixed in the Terraform except the cases below. Those are skipped **in the code next to the resource**, with the reason, using `#tfsec:ignore:<id>` and `# checkov:skip=<id>: <reason>`.

On the hardened Terraform, tfsec reports 0 problems (42 checks passed, 11 results ignored with a reason). Checkov reports 87 passed, 0 failed, 15 skipped (the reasons below).

## Justified skips

| Check | Resource | Reason |
|---|---|---|
| tfsec `aws-s3-enable-bucket-logging`, Checkov `CKV_AWS_18` | `aws_s3_bucket.log_bucket` | This bucket is the server access log target. Logging it to itself would create a loop. |
| tfsec `aws-s3-encryption-customer-key`, Checkov `CKV_AWS_145` | log bucket encryption | S3 server access logs can only be delivered to buckets encrypted with SSE-S3 (AES256), not SSE-KMS. |
| tfsec `aws-cloudtrail-ensure-cloudwatch-integration`, Checkov `CKV2_AWS_10` | `aws_cloudtrail.governance_trail` | Logs go to an encrypted, versioned S3 bucket with log file validation. CloudWatch Logs delivery (and its cost) is left out of this demo. Listed under future enhancements. |
| Checkov `CKV_AWS_252` | trail | No SNS consumer for trail notifications in this demo. |
| Checkov `CKV_AWS_144` | all four buckets | Single-region demo; cross-region replication isn't required. |
| Checkov `CKV2_AWS_62` | all four buckets | No downstream consumer for S3 event notifications. |
| tfsec `aws-iam-no-policy-wildcards` | `aws_iam_policy.s3_governance_policy` | `GetObject`/`PutObject` need `arn:...:bucket/*`. The wildcard is limited to objects in the one governed bucket. |
| Checkov `CKV_AWS_109`, `CKV_AWS_111`, `CKV_AWS_356` | KMS key policy document | In a KMS key policy, `"Resource": "*"` refers to the key itself; this is the documented form. |

## Notable fixes (not just scanner noise)

- **AWS Config recorder never started.** Terraform created the recorder but no `aws_config_configuration_recorder_status`, so recording stayed off unless someone started it by hand. Fixed, and an OPA policy now fails any change that defines a recorder without turning it on.
- **The log bucket received no logs.** It existed for access logs but no bucket was configured to send any. The other three buckets now log to it.
- **Hard-coded account ID** in two bucket policies is replaced by `aws_caller_identity`.

## Tools

Terraform, GitHub Actions, tfsec v1.28.0, Checkov 3.x, OPA / Conftest 0.56.0, AWS S3, KMS, CloudTrail, AWS Config, IAM.
