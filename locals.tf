locals {
  # WAF names and metric names allow word characters and hyphens only.
  # Underscore is kept rather than collapsed, or "my_app" and "my-app" would
  # sanitize to the same name and the second apply would collide.
  name = replace(var.name, "/[^a-zA-Z0-9_-]/", "-")

  # Paths are literal prefixes. Lowercased to pair with the LOWERCASE text
  # transformation on the match, then every regex metacharacter is escaped.
  # The bracket and backslash cases are not cosmetic: unescaped, "/user/[id]"
  # is a character class that matches "/user/i" and never matches itself, and
  # a trailing backslash produces a regex WAF rejects outright.
  escape_re      = "/([.^$*+?()|{}\\[\\]\\\\])/"
  upload_escaped = [for p in var.upload_paths : replace(lower(p), local.escape_re, "\\$1")]
  auth_escaped   = [for p in var.auth_rate_limit_paths : replace(lower(p), local.escape_re, "\\$1")]

  # WAF requires or_statement/and_statement to hold at least two children, so a
  # variable-length path list collapses into one anchored regex instead.
  upload_regex = length(local.upload_escaped) > 0 ? "^(${join("|", local.upload_escaped)})" : null
  auth_regex   = length(local.auth_escaped) > 0 ? "^(${join("|", local.auth_escaped)})" : null

  auth_rate_limit_enabled = local.auth_regex != null && var.auth_rate_limit > 0

  # WAF rejects the ":*" suffix the provider appends to a log group ARN.
  log_destination_arn = var.log_destination == "cloudwatch" ? trimsuffix(aws_cloudwatch_log_group.waf[0].arn, ":*") : var.log_bucket_arn
}
