variable "name" {
  description = "Name prefix. Characters outside letters, digits, underscore and hyphen collapse to hyphens."
  type        = string
  # The binding constraint is the metric name, which appends up to 17
  # characters against a 128 cap. Sanitizing is one for one, so this length is
  # exact. Unchecked, a long name applies fine and then fails only once an
  # optional managed group is enabled.
  validation {
    condition     = length(var.name) >= 1 && length(var.name) <= 111
    error_message = "name must be 1 to 111 characters, leaving room for the longest rule metric suffix."
  }
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}

variable "scope" {
  description = "CLOUDFRONT for edge distributions, REGIONAL for ALB, API Gateway and AppSync. A CLOUDFRONT ACL must be created in us-east-1; a REGIONAL ACL must be created in the protected resource's own region."
  type        = string
  default     = "CLOUDFRONT"
  validation {
    condition     = contains(["CLOUDFRONT", "REGIONAL"], var.scope)
    error_message = "scope must be CLOUDFRONT or REGIONAL."
  }
}

variable "default_action" {
  description = "Action for a request that matches no rule."
  type        = string
  default     = "allow"
  validation {
    condition     = contains(["allow", "block"], var.default_action)
    error_message = "default_action must be allow or block."
  }
}

## IP sets

# Terraform owns the allow and block lists. The bot list is left to an external
# writer (a honeypot, an abuse job) and its addresses are ignored on every plan.
# The allow rule is a TERMINATING allow at priority 0. An address listed here
# skips the block list, every managed group and both rate limits. That is a
# total bypass of the firewall, not a rate limit exemption, so it is validated
# far more strictly than the block lists: a wrong entry here fails open, while a
# wrong entry in a block list only fails closed.
# Never list a shared cloud egress range. Allow listing a hosted CI provider's
# published range hands the bypass to every other tenant using that range.
variable "allow_ipv4" {
  description = "IPv4 CIDRs that bypass EVERY rule. Use only for egress addresses you control, such as a static NAT for your own CI. CIDR notation is required, so a single address needs /32."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for c in var.allow_ipv4 : can(cidrhost(c, 0))])
    error_message = "allow_ipv4 entries must be CIDR notation, for example 203.0.113.7/32."
  }
  validation {
    condition     = alltrue([for c in var.allow_ipv4 : !can(cidrhost(c, 0)) || tonumber(split("/", c)[1]) >= 16])
    error_message = "allow_ipv4 entries must be /16 or narrower. A broader range grants a full firewall bypass to more addresses than anyone audits."
  }
}

variable "allow_ipv6" {
  description = "IPv6 CIDRs that bypass EVERY rule. Same caution as allow_ipv4."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for c in var.allow_ipv6 : can(cidrhost(c, 0))])
    error_message = "allow_ipv6 entries must be CIDR notation, for example 2001:db8::/48."
  }
  validation {
    condition     = alltrue([for c in var.allow_ipv6 : !can(cidrhost(c, 0)) || tonumber(split("/", c)[1]) >= 32])
    error_message = "allow_ipv6 entries must be /32 or narrower. A broader range grants a full firewall bypass to more addresses than anyone audits."
  }
}

variable "block_ipv4" {
  description = "IPv4 CIDRs blocked outright."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for c in var.block_ipv4 : can(cidrhost(c, 0))])
    error_message = "block_ipv4 entries must be CIDR notation, for example 198.51.100.0/24."
  }
}

variable "block_ipv6" {
  description = "IPv6 CIDRs blocked outright."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for c in var.block_ipv6 : can(cidrhost(c, 0))])
    error_message = "block_ipv6 entries must be CIDR notation, for example 2001:db8::/48."
  }
}

## Managed rule groups
# AWS Managed Rules carry no licence fee. Each group bills as one rule at 1 USD
# per month. Versions stay unpinned on purpose: AWS expires old static versions,
# so a pin is a scheduled outage.
# https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-changelog.html

variable "managed_rules_ip_reputation" {
  description = "AWSManagedRulesAmazonIpReputationList. Amazon threat intelligence, IP based only, never inspects a body. 25 WCU."
  type        = bool
  default     = true
}

variable "managed_rules_common" {
  description = "AWSManagedRulesCommonRuleSet. Broad OWASP style signatures. 700 WCU."
  type        = bool
  default     = true
}

variable "managed_rules_known_bad_inputs" {
  description = "AWSManagedRulesKnownBadInputsRuleSet. Known exploit payloads such as Log4j. 200 WCU. Part of the AWS recommended baseline alongside the common rule set."
  type        = bool
  default     = true
}

variable "managed_rules_sqli" {
  description = "AWSManagedRulesSQLiRuleSet. 200 WCU. On by default because the common rule set contains no SQL injection rules, and v2 of this module inspected for SQL injection unconditionally. Turning this off is a real reduction in coverage, not a saving."
  type        = bool
  default     = true
}

variable "count_only" {
  description = "Rule names to run in count mode instead of block. Deploy a new managed group here first, read the metrics, then remove it. Accepts: ip-reputation, common-rule-set, known-bad-inputs, sqli."
  type        = list(string)
  default     = []
  # An unrecognised name would otherwise be a silent no-op, leaving a group
  # blocking traffic while the operator believes it is only counting.
  validation {
    condition     = alltrue([for r in var.count_only : contains(["ip-reputation", "common-rule-set", "known-bad-inputs", "sqli"], r)])
    error_message = "count_only accepts only: ip-reputation, common-rule-set, known-bad-inputs, sqli."
  }
}

variable "excluded_rules" {
  description = "Per group, the rule names to downgrade to count. Keyed by group name, for example { common-rule-set = [\"GenericRFI_BODY\"] }. Reach for this before disabling a whole group over a single false positive, which is how 200 WCU of coverage gets thrown away to silence one rule."
  type        = map(list(string))
  default     = {}
  validation {
    condition     = alltrue([for k in keys(var.excluded_rules) : contains(["ip-reputation", "common-rule-set", "known-bad-inputs", "sqli"], k)])
    error_message = "excluded_rules keys must be one of: ip-reputation, common-rule-set, known-bad-inputs, sqli."
  }
}

variable "upload_paths" {
  description = "URI path prefixes exempt from the common rule set, for example [\"/upload/\"]. Large or binary uploads trip SizeRestrictions_BODY. Only that one group is skipped: the block list, the SQL injection group and both rate limits still apply. These are prefixes, so \"/upload\" also exempts \"/uploads-admin\"; include a trailing slash or the full path to keep the exemption tight. Matched literally, with regex metacharacters escaped and the path normalized before comparison."
  type        = list(string)
  default     = []
  # A bare "/" would match every request, silently disabling the entire common
  # rule set, so it is rejected rather than treated as a prefix.
  validation {
    condition     = alltrue([for p in var.upload_paths : startswith(p, "/") && length(p) >= 2])
    error_message = "upload_paths entries must start with / and be at least 2 characters. A bare / would exempt every request."
  }
}

## Rate limiting
# On by default: ASVS 2.4.1 and 6.1.1 rest entirely on these rules, and the
# whole cost is 1 USD per month per rule.

variable "rate_limit" {
  description = "Blanket requests per IP per evaluation window. 0 disables the rule, which fails ASVS 2.4.1."
  type        = number
  default     = 2000
  validation {
    condition     = var.rate_limit == 0 || var.rate_limit >= 10
    error_message = "rate_limit must be 0 or at least 10."
  }
}

variable "rate_limit_window_sec" {
  description = "Evaluation window for the blanket rate limit."
  type        = number
  default     = 300
  validation {
    condition     = contains([60, 120, 300, 600], var.rate_limit_window_sec)
    error_message = "rate_limit_window_sec must be 60, 120, 300 or 600."
  }
}

variable "auth_rate_limit_paths" {
  description = "URI path prefixes for the tighter authentication rate limit, for example [\"/login\", \"/signup\", \"/account/recovery\"]. Empty disables the rule. A blanket limit alone is too loose to stop credential stuffing, so ASVS 6.3.1 and 6.6.3 need this set. Matched literally: regex metacharacters are escaped."
  type        = list(string)
  default     = []
  # A bare "/" would apply the tight auth threshold to the whole site.
  validation {
    condition     = alltrue([for p in var.auth_rate_limit_paths : startswith(p, "/") && length(p) >= 2])
    error_message = "auth_rate_limit_paths entries must start with / and be at least 2 characters. A bare / would rate limit the whole site at the auth threshold."
  }
}

variable "auth_rate_limit" {
  description = "Requests per IP per window against auth_rate_limit_paths. 0 disables the rule even when auth_rate_limit_paths is set. Must be below rate_limit or the blanket rule catches the traffic first."
  type        = number
  default     = 100
  validation {
    condition     = var.auth_rate_limit == 0 || var.auth_rate_limit >= 10
    error_message = "auth_rate_limit must be 0 or at least 10."
  }
}

variable "auth_rate_limit_window_sec" {
  description = "Evaluation window for the authentication rate limit."
  type        = number
  default     = 300
  validation {
    condition     = contains([60, 120, 300, 600], var.auth_rate_limit_window_sec)
    error_message = "auth_rate_limit_window_sec must be 60, 120, 300 or 600."
  }
}

## Logging

variable "log_destination" {
  description = "cloudwatch creates a log group here. s3 uses log_bucket_arn. none disables logging, which loses the ASVS 16.3.3 evidence."
  type        = string
  default     = "cloudwatch"
  validation {
    condition     = contains(["cloudwatch", "s3", "none"], var.log_destination)
    error_message = "log_destination must be cloudwatch, s3 or none."
  }
}

variable "log_bucket_arn" {
  description = "S3 bucket ARN when log_destination is s3. AWS requires the bucket name to start with aws-waf-logs- and to sit in the same account and region as the ACL. AWS writes the bucket policy itself."
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "CloudWatch retention. With log_all_requests false the volume is a small fraction of traffic, so a long window stays cheap. 0 means never expire."
  type        = number
  default     = 90
  # CloudWatch Logs accepts only this set; anything else plans fine and fails on apply.
  validation {
    condition     = contains([0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be one of the values CloudWatch Logs accepts: 0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653."
  }
}

variable "log_kms_key_arn" {
  description = "Optional CMK for the CloudWatch log group. The key policy must allow the logs service principal for the ACL's region."
  type        = string
  default     = null
}

variable "log_all_requests" {
  description = "false keeps only blocked, counted, excluded-as-count, captcha and challenge records. Allowed requests are over 98 percent of traffic on a normal site, so this is the single largest logging cost lever. The trade is forensic: after an incident you cannot reconstruct what an attacker did on the requests the WAF allowed. Turn it on for an investigation, or when a compliance regime asks for full request logging."
  type        = bool
  default     = false
}

variable "redacted_headers" {
  description = "Headers masked in the logs. Lowercase. WAF logs still carry the client address, the URI and the query string, so this masks credentials rather than making the logs anonymous."
  type        = list(string)
  default     = ["authorization", "cookie"]
}
