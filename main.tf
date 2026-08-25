
# AWS Managed Rules, native rate limiting and native logging. No Lambda, no
# Firehose. Replaces the port of Security Automations for AWS WAF, which AWS
# retires in December 2026 in favour of exactly these native features.
# https://github.com/aws-solutions/aws-waf-security-automations

locals {
  # Priority order matters: the first terminating action wins.
  managed_groups = {
    "ip-reputation"    = { enabled = var.managed_rules_ip_reputation, priority = 2, group = "AWSManagedRulesAmazonIpReputationList" }
    "common-rule-set"  = { enabled = var.managed_rules_common, priority = 3, group = "AWSManagedRulesCommonRuleSet" }
    "known-bad-inputs" = { enabled = var.managed_rules_known_bad_inputs, priority = 4, group = "AWSManagedRulesKnownBadInputsRuleSet" }
    "sqli"             = { enabled = var.managed_rules_sqli, priority = 5, group = "AWSManagedRulesSQLiRuleSet" }
  }
  managed_enabled = { for k, v in local.managed_groups : k => v if v.enabled }

  # The allow rule is a full firewall bypass, so it is not created at all unless
  # someone actually populates a list. No dangling bypass in the default ACL.
  allow_list_enabled = length(var.allow_ipv4) + length(var.allow_ipv6) > 0
}

resource "aws_wafv2_web_acl" "main" {
  name        = "${local.name}-waf"
  description = "Allow list, block list, AWS Managed Rules and rate limits"
  scope       = var.scope
  tags        = var.tags

  lifecycle {
    # AWS caps a single regex pattern at 200 characters. Without these the limit
    # surfaces as an apply-time API error after the plan looked clean.
    precondition {
      condition     = local.upload_regex == null || length(local.upload_regex) <= 200
      error_message = "upload_paths compiles to a regex longer than the 200 character AWS limit. Use fewer or shorter prefixes."
    }
    precondition {
      condition     = local.auth_regex == null || length(local.auth_regex) <= 200
      error_message = "auth_rate_limit_paths compiles to a regex longer than the 200 character AWS limit. Use fewer or shorter prefixes."
    }
    # count_only only overrides a group that is already enabled, so naming a
    # disabled one produces no rule and an empty metric that reads as "no false
    # positives" to whoever is about to promote it to block.
    precondition {
      condition     = length(setsubtract(toset(var.count_only), toset(keys(local.managed_enabled)))) == 0
      error_message = "count_only names a managed group that is not enabled. Set the matching managed_rules_* variable to true as well."
    }
    precondition {
      condition     = var.managed_rules_common || length(var.upload_paths) == 0
      error_message = "upload_paths only affects the common rule set, which is disabled. Enable managed_rules_common or drop them."
    }
    precondition {
      condition     = length(setsubtract(toset(keys(var.excluded_rules)), toset(keys(local.managed_enabled)))) == 0
      error_message = "excluded_rules names a managed group that is not enabled, so those overrides do nothing."
    }
    # A web ACL with no managed group, no rate limit and no block list still
    # deploys, still shows up in the console, and inspects nothing. That reads
    # as protection to everyone who did not open it.
    precondition {
      condition     = length(local.managed_enabled) > 0 || var.rate_limit > 0 || local.auth_rate_limit_enabled || length(var.block_ipv4) + length(var.block_ipv6) > 0
      error_message = "This configuration inspects nothing: every managed group is off, no rate limit is set and both block lists are empty. Enable at least one control."
    }
    # Priority alone does not make the auth threshold win; it has to be lower.
    precondition {
      condition     = !local.auth_rate_limit_enabled || var.rate_limit == 0 || var.auth_rate_limit < var.rate_limit
      error_message = "auth_rate_limit must be below rate_limit, or the blanket rule catches the traffic before the tighter auth rule ever fires."
    }
    # Silently ignoring a logging variable is how someone ends up believing
    # their WAF logs are encrypted with a CMK that was never applied.
    precondition {
      condition     = var.log_kms_key_arn == null || var.log_destination == "cloudwatch"
      error_message = "log_kms_key_arn only applies to the CloudWatch log group this module creates. With s3 the bucket's own encryption governs."
    }
    precondition {
      condition     = var.log_bucket_arn == null || var.log_destination == "s3"
      error_message = "log_bucket_arn only applies when log_destination is s3."
    }
  }

  default_action {
    dynamic "allow" {
      for_each = var.default_action == "allow" ? [1] : []
      content {}
    }
    dynamic "block" {
      for_each = var.default_action == "block" ? [1] : []
      content {}
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    sampled_requests_enabled   = true
    metric_name                = "${local.name}-waf"
  }

  custom_response_body {
    key          = "rate-limit"
    content_type = "APPLICATION_JSON"
    content = jsonencode({
      status  = 429
      error   = "Too Many Requests"
      message = "Rate limit exceeded. Please retry later."
    })
  }

  # Priority 0, and Allow is terminating, so a listed address skips everything
  # below including the block list and the SQL injection group. That is the
  # point of an allow list, and also why it only exists when populated and why
  # allow_ipv4/allow_ipv6 carry a breadth limit the block lists do not.
  dynamic "rule" {
    for_each = local.allow_list_enabled ? [1] : []
    content {
      name     = "allow-list"
      priority = 0
      action {
        allow {}
      }
      statement {
        or_statement {
          statement {
            ip_set_reference_statement {
              arn = aws_wafv2_ip_set.allow_v4.arn
            }
          }
          statement {
            ip_set_reference_statement {
              arn = aws_wafv2_ip_set.allow_v6.arn
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "${local.name}-allow-list"
      }
    }
  }

  rule {
    name     = "block-list"
    priority = 1
    action {
      block {}
    }
    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.block_v4.arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.block_v6.arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.bot_v4.arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.bot_v6.arn
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      sampled_requests_enabled   = true
      metric_name                = "${local.name}-block-list"
    }
  }

  dynamic "rule" {
    for_each = local.managed_enabled
    content {
      name     = rule.key
      priority = rule.value.priority

      override_action {
        dynamic "count" {
          for_each = contains(var.count_only, rule.key) ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = contains(var.count_only, rule.key) ? [] : [1]
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.group
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = lookup(var.excluded_rules, rule.key, [])
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }

          # Upload paths skip this group only. The block list and both rate
          # limits still apply, unlike the blanket allow this replaces.
          dynamic "scope_down_statement" {
            for_each = rule.key == "common-rule-set" && local.upload_regex != null ? [1] : []
            content {
              not_statement {
                statement {
                  regex_match_statement {
                    regex_string = local.upload_regex
                    field_to_match {
                      uri_path {}
                    }
                    # Matches the normalization applied to the auth rule below.
                    text_transformation {
                      priority = 0
                      type     = "URL_DECODE"
                    }
                    text_transformation {
                      priority = 1
                      type     = "NORMALIZE_PATH"
                    }
                    text_transformation {
                      priority = 2
                      type     = "LOWERCASE"
                    }
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "${local.name}-${rule.key}"
      }
    }
  }

  # Ahead of the blanket limit so the tighter auth threshold wins on those paths.
  dynamic "rule" {
    for_each = local.auth_rate_limit_enabled ? [1] : []
    content {
      name     = "rate-limit-auth"
      priority = 10
      action {
        block {
          custom_response {
            response_code            = 429
            custom_response_body_key = "rate-limit"
          }
        }
      }
      statement {
        rate_based_statement {
          aggregate_key_type    = "IP"
          limit                 = var.auth_rate_limit
          evaluation_window_sec = var.auth_rate_limit_window_sec
          scope_down_statement {
            regex_match_statement {
              regex_string = local.auth_regex
              field_to_match {
                uri_path {}
              }
              # Without these, "//login", "/./login", "/%6Cogin" and "/Login"
              # all miss the scope-down and fall through to the far looser
              # blanket limit, which is the whole credential stuffing budget.
              # 10 WCU each, and only on this optional rule.
              text_transformation {
                priority = 0
                type     = "URL_DECODE"
              }
              text_transformation {
                priority = 1
                type     = "NORMALIZE_PATH"
              }
              text_transformation {
                priority = 2
                type     = "LOWERCASE"
              }
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "${local.name}-rate-limit-auth"
      }
    }
  }

  # Aggregates per distinct address. WAF exposes no IPv6 prefix option, so a
  # client holding a /64 can rotate past this. The ASN aggregation key is the
  # upgrade path if the logs ever show that.
  # https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based-aggregation-options.html
  dynamic "rule" {
    for_each = var.rate_limit > 0 ? [1] : []
    content {
      name     = "rate-limit"
      priority = 11
      action {
        block {
          custom_response {
            response_code            = 429
            custom_response_body_key = "rate-limit"
          }
        }
      }
      statement {
        rate_based_statement {
          aggregate_key_type    = "IP"
          limit                 = var.rate_limit
          evaluation_window_sec = var.rate_limit_window_sec
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "${local.name}-rate-limit"
      }
    }
  }
}
