
output "arn" {
  description = "Web ACL ARN. CloudFront distributions and aws_wafv2_web_acl_association both take the ARN."
  value       = aws_wafv2_web_acl.main.arn
}

output "id" {
  description = "Web ACL id. In v2 this output returned the ARN."
  value       = aws_wafv2_web_acl.main.id
}

output "name" {
  value = aws_wafv2_web_acl.main.name
}

output "capacity" {
  description = "Consumed WCU. A web ACL defaults to a 1500 WCU ceiling."
  value       = aws_wafv2_web_acl.main.capacity
}

output "log_group_name" {
  description = "Null unless log_destination is cloudwatch."
  value       = var.log_destination == "cloudwatch" ? aws_cloudwatch_log_group.waf[0].name : null
}

# For an external writer such as an API honeypot. UpdateIPSet needs Name,
# Scope, Id and LockToken, so the names are exported alongside the ids.
output "ipset_bot_v4_name" {
  value = aws_wafv2_ip_set.bot_v4.name
}

output "ipset_bot_v6_name" {
  value = aws_wafv2_ip_set.bot_v6.name
}

output "scope" {
  description = "Pass to UpdateIPSet alongside the bot set name and id."
  value       = var.scope
}

output "ipset_bot_v4_arn" {
  value = aws_wafv2_ip_set.bot_v4.arn
}

output "ipset_bot_v6_arn" {
  value = aws_wafv2_ip_set.bot_v6.arn
}

output "ipset_bot_v4_id" {
  value = aws_wafv2_ip_set.bot_v4.id
}

output "ipset_bot_v6_id" {
  value = aws_wafv2_ip_set.bot_v6.id
}
