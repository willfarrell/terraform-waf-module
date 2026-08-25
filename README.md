# Web Application Firewall (WAF)

A WAFv2 web ACL for CloudFront, ALB, API Gateway and AppSync. AWS Managed Rules, native rate limiting and native logging. No Lambda, no Firehose, no IAM roles.

v3 replaced the port of [Security Automations for AWS WAF](https://github.com/aws-solutions/aws-waf-security-automations), which AWS retires in December 2026 and tells customers to replace with exactly these native features. For the old Lambda pipeline see `<=v2.5.0`. For Classic WAF see `<=v0.0.4`.

## Setup

```hcl
module "waf" {
  source = "github.com/willfarrell/terraform-waf-module?ref=v3.0.0"
  name   = local.workspace["name"]
  tags   = local.workspace["tags"]

  # A CLOUDFRONT ACL must be created in us-east-1.
  providers = {
    aws = aws.edge
  }
}

resource "aws_cloudfront_distribution" "www" {
  web_acl_id = module.waf.arn
  # ...
}
```

REGIONAL is the same module with `scope = "REGIONAL"`, created in the protected resource's own region, and attached with `aws_wafv2_web_acl_association` rather than an argument on the resource.

An external writer such as an API honeypot takes the bot IP set and adds addresses to it. Terraform creates the set and never reconciles its contents.

`UpdateIPSet` needs the name, scope, id and a lock token, so the module exports `ipset_bot_v4_name`, `ipset_bot_v6_name` and `scope` alongside the ids.

Nothing ages those entries out, and AWS caps an IP set at 10,000 addresses, so a writer that only ever adds will eventually fill it. Expiry is deliberately not built here: a WAF IP set carries no per-entry timestamp, so it needs a scheduled job and a store of its own. Add it when the set actually fills.

Changing `scope` on a live stack replaces the IP sets, and everything an external writer put in them is lost. `ignore_changes` protects contents against drift, not against replacement.

```hcl
resource "aws_ssm_parameter" "bad-bot-ipv4" {
  name  = "/infrastructure/waf/bad-bot-ipv4"
  type  = "String"
  value = module.waf.ipset_bot_v4_id
}
```

## Rules

Priority order. The first terminating action wins.

| Priority | Rule | Default | Notes |
|---|---|---|---|
| 0 | `allow-list` | absent | Created only when `allow_ipv4` or `allow_ipv6` is populated. See the warning below. |
| 1 | `block-list` | on | Manual block IP sets plus the externally written bot sets. |
| 2 | `ip-reputation` | on | `AWSManagedRulesAmazonIpReputationList`, 25 WCU. |
| 3 | `common-rule-set` | on | `AWSManagedRulesCommonRuleSet`, 700 WCU. Contains no SQL injection rules. |
| 4 | `known-bad-inputs` | on | `AWSManagedRulesKnownBadInputsRuleSet`, 200 WCU. |
| 5 | `sqli` | on | `AWSManagedRulesSQLiRuleSet`, 200 WCU. |
| 10 | `rate-limit-auth` | off | Set `auth_rate_limit_paths` to enable. |
| 11 | `rate-limit` | on | Blanket per IP. |

### The allow list is a firewall bypass, not a rate limit exemption

`allow-list` acts at priority 0 and Allow is a terminating action, so a listed address skips the block list, every managed group and both rate limits. It is not created at all unless you populate a list, and `allow_ipv4` and `allow_ipv6` are capped at /16 and /32 respectively, because a wrong entry here fails open. The block lists carry no such cap: blocking too widely fails closed.

Never list a shared cloud egress range. Allow listing a hosted CI provider's published addresses hands the bypass to every other tenant on those addresses.

Managed rule versions stay unpinned. AWS expires old static versions, so a pin is a scheduled outage.

To roll a new managed group out safely, set both its `managed_rules_*` flag and its name in `count_only`, read the CloudWatch metrics, then remove it from `count_only`. `count_only` alone does nothing: it overrides a group that is already enabled, so naming a disabled group would give you an empty metric that looks like a clean result. The module rejects that combination rather than letting it mislead you.

Path matching on `upload_paths` and `auth_rate_limit_paths` is normalized before comparison, with URL decoding, path normalization and lowercasing, so `//Login` and `/%6Cogin` cannot slip past a rule configured for `/login`. Each transformation costs 10 WCU and applies only to those optional rules.

A web ACL has a hard 5000 WCU ceiling that no quota request can raise, and anything above 1500 WCU bills beyond the base web ACL price. The defaults consume at most about 1131: 700 for the core rule set, 200 each for known bad inputs and SQL injection, 25 for the IP reputation list, and single digits for the IP set and rate statements. Turning on both optional path rules adds a regex plus three text transformations each, roughly 35 WCU apiece, for about 1201. Every combination this module can produce stays under the 1500 threshold, so the extra charge never applies unless you add rules of your own.

## Cost

| Item | Cost |
|---|---|
| Web ACL | 5.00 USD per month |
| Each rule, managed group included | 1.00 USD per month |
| Requests | 0.60 USD per million |

AWS Managed Rules carry no licence fee and each group bills as a single rule. That holds for the four groups here, but not for Bot Control or Fraud Control, which carry their own subscription and per-request fees and are not used.

The default configuration is six rules, so 11.00 USD per month plus request charges. Populating an allow list makes it 12.00, and adding the authentication rate limit 13.00.

CAPTCHA and Challenge both bill per use and neither is used.

## Logging

Default is a CloudWatch log group named `aws-waf-logs-<name>`, created by the module. AWS requires that name prefix on every destination type. Set `log_destination = "s3"` with `log_bucket_arn` for high volume; the bucket name must also start with `aws-waf-logs-`. AWS writes the resource policy or bucket policy itself.

`log_all_requests` defaults to false, which keeps blocked, counted, excluded-as-count, captcha and challenge records. Allowed requests are over 98 percent of traffic on a normal site. At 10 million requests a month, logging everything to CloudWatch costs roughly 7.50 USD and the filtered version costs under a dollar.

`authorization` and `cookie` are redacted by default.

## Compliance

The defaults satisfy OWASP ASVS 5.0 2.4.1 and 6.1.1, which both rest entirely on the rate limiting rules. Setting `rate_limit = 0` fails both.

ASVS 6.3.1 and 6.6.3 need `auth_rate_limit_paths` set. A blanket limit loose enough not to disturb normal browsing still allows thousands of login attempts, which is a comfortable budget for credential stuffing.

ASVS 16.3.3 wants anti automation hits logged. The default logging filter keeps them, but the control also wants a documented security event list and those events in the application's own log, which is caller work.

One caveat undercuts all of the above. If the origin stays reachable without going through the edge, for example a Lambda function URL with `auth_type = "NONE"`, then the ACL is not on the only path to the origin and nothing it enforces is guaranteed. See ASVS 15.3.4.

## Tests

```sh
tofu init -backend=false && tofu test
```

Twenty six plan only runs against a mocked provider, so no credentials and no AWS calls. Several exist to pin a security property rather than a behaviour: that SQL injection is inspected by default, that no bypass rule is created unless a list is populated, that an over-broad allow list is refused while a broad block list is not, and that a configuration inspecting nothing is refused outright. The rest cover rule composition, path escaping and each input guardrail.

## Inputs

See `variables.tf`. Every variable carries a description.

## Outputs

- **arn:** web ACL ARN. CloudFront and `aws_wafv2_web_acl_association` both take this.
- **id:** web ACL id. In v2 this output returned the ARN.
- **name**, **capacity**, **log_group_name**
- **ipset_bot_v4_arn**, **ipset_bot_v6_arn**, **ipset_bot_v4_id**, **ipset_bot_v6_id**
- **ipset_bot_v4_name**, **ipset_bot_v6_name**, **scope** for an external writer calling `UpdateIPSet`

## Migrating from v2

Breaking. Read before upgrading a live ACL.

**Coverage differences, first.** v2 ran a hand written SQL injection rule and a hand written XSS rule unconditionally. In v3 the XSS coverage moves into the common rule set, which is on by default, and SQL injection moves to `AWSManagedRulesSQLiRuleSet`. That group is on by default precisely so the upgrade does not quietly drop the check, but if you set `managed_rules_sqli = false` you end up with less coverage than v2 had, because the common rule set contains no SQL injection rules. `known-bad-inputs` is new and also on by default. If either group false-positives, put it in `count_only` or use `excluded_rules` on the offending rule rather than turning the group off.

v2 also redacted `user-agent` from the logs. v3 redacts `authorization` and `cookie` only, since the user agent string is one of the more useful fields for identifying a bad bot. Add it back through `redacted_headers` if you would rather not keep it.

1. `output "id"` returned the ARN and now returns the id. Switch consumers to `arn`.
2. The bad bot outputs are renamed from `ipset_bad-bot-v4_id` to `ipset_bot_v4_id`.
3. Six IP sets are gone: the HTTP flood, scanners and probes, and reputation list pairs. The Lambdas that wrote them are deleted, and `AWSManagedRulesAmazonIpReputationList` replaces the last of those.
4. `dead_letter_arn`, `dead_letter_policy_arn`, `kms_master_key_id`, `kms_master_key_arn` and `logging_bucket` are gone. Logging takes `log_destination`, `log_bucket_arn` and `log_kms_key_arn`.
5. `uploadToS3Activated`, `uploadToS3Path` and `uploadToS3Method` become `upload_paths`. The old rule was a blanket allow at priority 0, which skipped every later rule including the block list. The replacement exempts those paths from the common rule set only.
6. `excluded_rules` changes from a list to a map keyed by group, so `["GenericRFI_BODY"]` becomes `{ common-rule-set = ["GenericRFI_BODY"] }`. It now works for any enabled group rather than the common rule set alone.
7. `whitelistActivated`, `blacklistProtectionActivated`, `httpFloodProtectionLogParserActivated`, `scannersProbesProtectionActivated`, `reputationListsProtectionActivated` and `badBotProtectionActivated` are gone. The block rule is always present, the allow rule appears when you populate a list, and the managed groups have their own flags.
8. The allow list moved from priority 3 to priority 0, so it now bypasses the managed groups as well. In v2 a whitelisted address was still inspected by the common rule set. Entries are capped at /16 and /32 to bound that.
9. `requestThreshold` becomes `rate_limit`, `errorThreshold` and `blockPeriod` are gone with the log parser.
10. `defaultAction` becomes `default_action` and is now actually wired. In v2 the variable was read nowhere and the ACL always allowed.

## Sources

- [AWS Managed Rules changelog](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-changelog.html)
- [Rate based rule aggregation options](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based-aggregation-options.html)
- [Logging web ACL traffic](https://docs.aws.amazon.com/waf/latest/developerguide/logging.html)
- [AWS WAF pricing](https://aws.amazon.com/waf/pricing/)
