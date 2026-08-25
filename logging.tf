
# WAF writes straight to CloudWatch or S3. Firehose has not been required since
# 2021. AWS creates the resource policy or bucket policy itself when the logging
# configuration is put, so this module needs no IAM role.
# https://docs.aws.amazon.com/waf/latest/developerguide/logging-s3.html

resource "aws_cloudwatch_log_group" "waf" {
  count = var.log_destination == "cloudwatch" ? 1 : 0

  # WAF rejects any destination whose name does not start with aws-waf-logs-.
  name              = "aws-waf-logs-${local.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
  tags              = var.tags
}

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count = var.log_destination == "none" ? 0 : 1

  # Without this the omission surfaces as "Null value found in list" against a
  # line that never mentions the missing variable.
  lifecycle {
    precondition {
      condition     = var.log_destination != "s3" || var.log_bucket_arn != null
      error_message = "log_destination is s3, so log_bucket_arn is required. The bucket name must start with aws-waf-logs-."
    }
  }

  resource_arn            = aws_wafv2_web_acl.main.arn
  log_destination_configs = [local.log_destination_arn]

  dynamic "redacted_fields" {
    for_each = var.redacted_headers
    content {
      single_header {
        name = redacted_fields.value
      }
    }
  }

  # Drop the allowed requests. They are over 98 percent of traffic on a normal
  # site and none of them is evidence of anything.
  dynamic "logging_filter" {
    for_each = var.log_all_requests ? [] : [1]
    content {
      default_behavior = "DROP"
      filter {
        behavior    = "KEEP"
        requirement = "MEETS_ANY"
        # EXCLUDED_AS_COUNT is separate from COUNT: a per-rule override from
        # excluded_rules logs under that action, and the COUNT condition does
        # not match it. Without it the exclusion's own evidence is dropped.
        dynamic "condition" {
          for_each = ["BLOCK", "COUNT", "EXCLUDED_AS_COUNT", "CAPTCHA", "CHALLENGE"]
          content {
            action_condition {
              action = condition.value
            }
          }
        }
      }
    }
  }
}
