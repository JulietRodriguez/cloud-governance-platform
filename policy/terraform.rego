# Policy-as-code guardrails for the Terraform in ../terraform.
#
# Run:  conftest test --parser hcl2 --combine terraform/*.tf
#
# --combine passes every .tf file at once as a list of {path, contents}, so a
# rule can check one resource against another (for example, that each bucket
# has a public access block). The checks mirror the governance controls in the
# README, so a pull request that removes one fails CI.
package main

import rego.v1

required_tags := {"Project", "Environment", "Owner", "ManagedBy"}

# All resources of one type across every file: name -> config.
resources(rtype) := {name: cfg |
	some file in input
	some name, cfg in file.contents.resource[rtype]
}

buckets := resources("aws_s3_bucket")

# True if cfg.bucket references aws_s3_bucket.<name> (e.g. "${aws_s3_bucket.secure_bucket.id}").
references_bucket(cfg, name) if contains(cfg.bucket, sprintf("aws_s3_bucket.%s.", [name]))

# ---------- S3 ----------

deny contains msg if {
	some name, bucket in buckets
	missing := required_tags - {k | some k, _ in object.get(bucket, "tags", {})}
	count(missing) > 0
	msg := sprintf("aws_s3_bucket.%s is missing required tags: %v", [name, sort(missing)])
}

deny contains msg if {
	some name, _ in buckets
	not has_full_public_access_block(name)
	msg := sprintf("aws_s3_bucket.%s needs a public access block with all four settings true", [name])
}

has_full_public_access_block(name) if {
	some _, pab in resources("aws_s3_bucket_public_access_block")
	references_bucket(pab, name)
	pab.block_public_acls == true
	pab.block_public_policy == true
	pab.ignore_public_acls == true
	pab.restrict_public_buckets == true
}

deny contains msg if {
	some name, _ in buckets
	not has_encryption(name)
	msg := sprintf("aws_s3_bucket.%s has no server-side encryption configuration", [name])
}

has_encryption(name) if {
	some _, enc in resources("aws_s3_bucket_server_side_encryption_configuration")
	references_bucket(enc, name)
}

deny contains msg if {
	some name, _ in buckets
	not has_versioning(name)
	msg := sprintf("aws_s3_bucket.%s must have versioning enabled", [name])
}

has_versioning(name) if {
	some _, ver in resources("aws_s3_bucket_versioning")
	references_bucket(ver, name)
	ver.versioning_configuration.status == "Enabled"
}

# ---------- CloudTrail ----------

deny contains msg if {
	some name, trail in resources("aws_cloudtrail")
	some setting in ["is_multi_region_trail", "enable_log_file_validation"]
	object.get(trail, setting, false) != true
	msg := sprintf("aws_cloudtrail.%s must set %s = true", [name, setting])
}

deny contains msg if {
	some name, trail in resources("aws_cloudtrail")
	not trail.kms_key_id
	msg := sprintf("aws_cloudtrail.%s must encrypt logs with a KMS key (kms_key_id)", [name])
}

# ---------- KMS ----------

deny contains msg if {
	some name, key in resources("aws_kms_key")
	object.get(key, "enable_key_rotation", false) != true
	msg := sprintf("aws_kms_key.%s must enable key rotation", [name])
}

# ---------- AWS Config ----------

deny contains msg if {
	count(resources("aws_config_configuration_recorder")) > 0
	not recorder_enabled
	msg := "AWS Config recorder is defined but no aws_config_configuration_recorder_status turns it on (is_enabled = true)"
}

recorder_enabled if {
	some _, status in resources("aws_config_configuration_recorder_status")
	status.is_enabled == true
}
