package iso27001.iac.a8_24

import rego.v1

# Default rule: bucket is non-compliant unless SSE resource exists
default allow := false

# Identify all created/updated S3 buckets in the plan
proposed_s3_buckets contains bucket if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] in ["create", "update"]
    bucket := resource.change.after.bucket
}

# Identify all buckets with an explicit encryption block attached
encrypted_s3_buckets contains bucket_ref if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] in ["create", "update"]
    
    # Handle direct string bucket or reference
    bucket_ref := resource.change.after.bucket
}

# Generate findings for unencrypted buckets
violations contains violation if {
    some bucket in proposed_s3_buckets
    not bucket in encrypted_s3_buckets
    
    violation := {
        "control_id": "A.8.24",
        "rule_id": "iac_s3_encryption_missing",
        "severity": "high",
        "resource": bucket,
        "message": sprintf("S3 bucket '%s' planned for creation without AES256/KMS encryption.", [bucket])
    }
}