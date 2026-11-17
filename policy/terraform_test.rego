package main

import rego.v1

# Unit tests for terraform.rego. Run: conftest verify --policy policy

good := [{
	"path": "main.tf",
	"contents": {"resource": {
		"aws_s3_bucket": {"b": {"bucket": "x", "tags": {"Project": "p", "Environment": "dev", "Owner": "o", "ManagedBy": "Terraform"}}},
		"aws_s3_bucket_public_access_block": {"b": {
			"bucket": "${aws_s3_bucket.b.id}",
			"block_public_acls": true, "block_public_policy": true,
			"ignore_public_acls": true, "restrict_public_buckets": true,
		}},
		"aws_s3_bucket_server_side_encryption_configuration": {"b": {"bucket": "${aws_s3_bucket.b.id}"}},
		"aws_s3_bucket_versioning": {"b": {"bucket": "${aws_s3_bucket.b.id}", "versioning_configuration": {"status": "Enabled"}}},
		"aws_cloudtrail": {"t": {"is_multi_region_trail": true, "enable_log_file_validation": true, "kms_key_id": "${aws_kms_key.k.arn}"}},
		"aws_kms_key": {"k": {"enable_key_rotation": true}},
		"aws_config_configuration_recorder": {"r": {"name": "r"}},
		"aws_config_configuration_recorder_status": {"r": {"is_enabled": true}},
	}},
}]

# Replaces every resource of rtype with the single {name: cfg}.
with_resource(rtype, name, cfg) := [{
	"path": "main.tf",
	"contents": {"resource": object.union(object.remove(good[0].contents.resource, [rtype]), {rtype: {name: cfg}})},
}]

test_compliant_config_passes if {
	count(deny) == 0 with input as good
}

test_missing_tag_denied if {
	bad := with_resource("aws_s3_bucket", "b", {"bucket": "x", "tags": {"Project": "p"}})
	some msg in deny with input as bad
	contains(msg, "missing required tags")
}

test_bucket_without_public_access_block_denied if {
	bad := with_resource("aws_s3_bucket", "other", {"tags": good[0].contents.resource.aws_s3_bucket.b.tags})
	msgs := deny with input as bad
	some msg in msgs
	contains(msg, "aws_s3_bucket.other needs a public access block")
}

test_partial_public_access_block_denied if {
	bad := with_resource("aws_s3_bucket_public_access_block", "b", {"bucket": "${aws_s3_bucket.b.id}", "block_public_acls": true})
	some msg in deny with input as bad
	contains(msg, "public access block")
}

test_suspended_versioning_denied if {
	bad := with_resource("aws_s3_bucket_versioning", "b", {"bucket": "${aws_s3_bucket.b.id}", "versioning_configuration": {"status": "Suspended"}})
	some msg in deny with input as bad
	contains(msg, "versioning")
}

test_single_region_trail_denied if {
	bad := with_resource("aws_cloudtrail", "t", {"enable_log_file_validation": true, "kms_key_id": "k"})
	some msg in deny with input as bad
	contains(msg, "is_multi_region_trail")
}

test_unencrypted_trail_denied if {
	bad := with_resource("aws_cloudtrail", "t", {"is_multi_region_trail": true, "enable_log_file_validation": true})
	some msg in deny with input as bad
	contains(msg, "kms_key_id")
}

test_key_without_rotation_denied if {
	bad := with_resource("aws_kms_key", "k", {"enable_key_rotation": false})
	some msg in deny with input as bad
	contains(msg, "key rotation")
}

test_stopped_config_recorder_denied if {
	bad := with_resource("aws_config_configuration_recorder_status", "r", {"is_enabled": false})
	some msg in deny with input as bad
	contains(msg, "recorder")
}
