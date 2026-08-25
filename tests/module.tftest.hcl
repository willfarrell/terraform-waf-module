# Run with: tofu test
# No credentials needed; the provider is mocked and every run is plan only.

# The generated mock ids fail the provider's own ARN validation, so the ARN
# shaped attributes need real looking values.
mock_provider "aws" {
  mock_resource "aws_wafv2_ip_set" {
    defaults = {
      arn = "arn:aws:wafv2:us-east-1:111122223333:global/ipset/mock/11111111-1111-1111-1111-111111111111"
    }
  }
  mock_resource "aws_wafv2_web_acl" {
    defaults = {
      arn = "arn:aws:wafv2:us-east-1:111122223333:global/webacl/mock/22222222-2222-2222-2222-222222222222"
    }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-1:111122223333:log-group:aws-waf-logs-mock"
    }
  }
}

variables {
  name = "example.com"
}

run "defaults_render_six_rules" {
  command = plan

  assert {
    condition     = length(aws_wafv2_web_acl.main.rule) == 6
    error_message = "Default posture must be exactly 6 rules, which is the 11 USD per month figure in the README."
  }
}

# v2 of this module inspected for SQL injection unconditionally, and the common
# rule set contains no SQLi rules. Defaulting this off is a silent loss of
# coverage for anyone upgrading, so it is pinned by a test.
run "sql_injection_is_inspected_by_default" {
  command = plan

  assert {
    condition     = length([for r in aws_wafv2_web_acl.main.rule : r if r.name == "sqli"]) == 1
    error_message = "The SQL injection group must be on by default."
  }
}

# A terminating allow at priority 0 bypasses every other rule, so it must not
# exist at all unless someone populated a list.
run "no_bypass_rule_exists_unless_asked_for" {
  command = plan

  assert {
    condition     = length([for r in aws_wafv2_web_acl.main.rule : r if r.name == "allow-list"]) == 0
    error_message = "The allow list rule must not be created when both allow lists are empty."
  }
}

run "allow_list_appears_and_outranks_everything_when_populated" {
  command = plan
  variables {
    allow_ipv4 = ["203.0.113.7/32"]
  }

  assert {
    condition     = one([for r in aws_wafv2_web_acl.main.rule : r.priority if r.name == "allow-list"]) == 0
    error_message = "A populated allow list must sit at priority 0."
  }
}

run "rejects_an_overbroad_allow_list" {
  command = plan
  variables {
    allow_ipv4 = ["10.0.0.0/8"]
  }
  expect_failures = [var.allow_ipv4]
}

run "rejects_allowing_the_entire_internet" {
  command = plan
  variables {
    allow_ipv4 = ["0.0.0.0/0"]
  }
  expect_failures = [var.allow_ipv4]
}

# Broad blocks fail closed, so they are deliberately not constrained.
run "permits_a_broad_block_list" {
  command = plan
  variables {
    block_ipv4 = ["10.0.0.0/8"]
  }

  assert {
    condition     = length([for r in aws_wafv2_web_acl.main.rule : r if r.name == "block-list"]) == 1
    error_message = "Block lists carry no breadth limit; blocking widely fails closed."
  }
}

run "rejects_a_web_acl_that_inspects_nothing" {
  command = plan
  variables {
    managed_rules_ip_reputation    = false
    managed_rules_common           = false
    managed_rules_known_bad_inputs = false
    managed_rules_sqli             = false
    rate_limit                     = 0
  }
  expect_failures = [aws_wafv2_web_acl.main]
}

# ASVS 2.4.1 and 6.1.1 rest entirely on this rule. If a future edit defaults it
# off to save a dollar, both controls fail and this test is the tripwire.
run "rate_limit_is_on_by_default" {
  command = plan

  assert {
    condition     = length([for r in aws_wafv2_web_acl.main.rule : r if r.name == "rate-limit"]) == 1
    error_message = "The blanket rate limit must be on by default."
  }
}

run "auth_paths_add_the_tighter_rule" {
  command = plan
  variables {
    auth_rate_limit_paths = ["/login", "/signup"]
  }

  assert {
    condition     = length([for r in aws_wafv2_web_acl.main.rule : r if r.name == "rate-limit-auth"]) == 1
    error_message = "Setting auth_rate_limit_paths must create the authentication rate limit rule."
  }
  assert {
    condition     = one([for r in aws_wafv2_web_acl.main.rule : r.priority if r.name == "rate-limit-auth"]) < one([for r in aws_wafv2_web_acl.main.rule : r.priority if r.name == "rate-limit"])
    error_message = "The auth rate limit must be evaluated before the blanket limit or the tighter threshold never applies."
  }
}

run "disabling_a_group_removes_its_rule" {
  command = plan
  variables {
    managed_rules_known_bad_inputs = false
  }

  assert {
    condition     = length(aws_wafv2_web_acl.main.rule) == 5
    error_message = "Turning a managed group off should remove exactly that rule."
  }
}

# Per group overrides exist so one false positive does not cost a whole group.
run "overrides_apply_to_a_non_crs_group" {
  command = plan
  variables {
    excluded_rules = { sqli = ["SQLi_BODY"] }
  }

  assert {
    condition     = length(aws_wafv2_web_acl.main.rule) == 6
    error_message = "An excluded_rules entry for the sqli group must be accepted."
  }
}

run "rejects_overrides_for_a_disabled_group" {
  command = plan
  variables {
    managed_rules_sqli = false
    excluded_rules     = { sqli = ["SQLi_BODY"] }
  }
  expect_failures = [aws_wafv2_web_acl.main]
}

run "logging_drops_allowed_requests_by_default" {
  command = plan

  assert {
    condition     = length(aws_wafv2_web_acl_logging_configuration.main[0].logging_filter) == 1
    error_message = "The logging filter must be present by default; it is the main logging cost lever."
  }
}

## Guardrails. Each of these was a silent failure before it was caught.

run "rejects_unknown_count_only_name" {
  command = plan
  variables {
    count_only = ["CommonRuleSet"]
  }
  expect_failures = [var.count_only]
}

run "rejects_path_without_leading_slash" {
  command = plan
  variables {
    upload_paths = ["upload"]
  }
  expect_failures = [var.upload_paths]
}

run "rejects_s3_logging_without_a_bucket" {
  command = plan
  variables {
    log_destination = "s3"
  }
  expect_failures = [aws_wafv2_web_acl_logging_configuration.main]
}

# Unescaped, "/user/[id]" is a live character class: it matches "/user/i" and
# never matches the literal path, so the endpoint gets no rate limit at all.
run "escapes_regex_metacharacters_in_paths" {
  command = plan
  variables {
    auth_rate_limit_paths = ["/user/[id]/recovery"]
  }

  assert {
    condition = strcontains(
      one([
        for r in tolist(aws_wafv2_web_acl.main.rule) : tolist(r.statement)[0].rate_based_statement[0].scope_down_statement[0].regex_match_statement[0].regex_string
        if r.name == "rate-limit-auth"
      ]),
      "\\[id\\]"
    )
    error_message = "Regex metacharacters in a path must be escaped."
  }
}

run "rejects_a_bare_slash_path" {
  command = plan
  variables {
    upload_paths = ["/"]
  }
  # "^(/)" matches every request, which would silently disable the whole
  # common rule set.
  expect_failures = [var.upload_paths]
}

run "rejects_count_only_for_a_disabled_group" {
  command = plan
  variables {
    managed_rules_sqli = false
    count_only         = ["sqli"]
  }
  expect_failures = [aws_wafv2_web_acl.main]
}

run "rejects_auth_limit_above_the_blanket_limit" {
  command = plan
  variables {
    auth_rate_limit_paths = ["/login"]
    auth_rate_limit       = 5000
    rate_limit            = 2000
  }
  expect_failures = [aws_wafv2_web_acl.main]
}

run "rejects_upload_paths_without_the_common_rule_set" {
  command = plan
  variables {
    managed_rules_common = false
    upload_paths         = ["/upload"]
  }
  expect_failures = [aws_wafv2_web_acl.main]
}

run "rejects_a_bare_address_without_a_prefix" {
  command = plan
  variables {
    allow_ipv4 = ["203.0.113.7"]
  }
  expect_failures = [var.allow_ipv4]
}

run "rejects_a_logging_variable_that_would_be_ignored" {
  command = plan
  variables {
    log_destination = "s3"
    log_bucket_arn  = "arn:aws:s3:::aws-waf-logs-example"
    log_kms_key_arn = "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-1111-1111-111111111111"
  }
  expect_failures = [aws_wafv2_web_acl.main]
}

run "rejects_an_invalid_retention_value" {
  command = plan
  variables {
    log_retention_days = 100
  }
  expect_failures = [var.log_retention_days]
}

run "rejects_paths_that_overflow_the_regex_limit" {
  command = plan
  variables {
    upload_paths = ["/upload/bucket00", "/upload/bucket01", "/upload/bucket02", "/upload/bucket03", "/upload/bucket04", "/upload/bucket05", "/upload/bucket06", "/upload/bucket07", "/upload/bucket08", "/upload/bucket09", "/upload/bucket10", "/upload/bucket11"]
  }
  expect_failures = [aws_wafv2_web_acl.main]
}
