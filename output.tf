output "id" {
  value = aws_wafv2_web_acl.main.arn
}

output "ipset_bad-bot-v4_arn" {
  value = aws_wafv2_ip_set.IPBadBotSetIPV4.arn
}
output "ipset_bad-bot-v6_arn" {
  value = aws_wafv2_ip_set.IPBadBotSetIPV6.arn
}

output "ipset_bad-bot-v4_id" {
  value = aws_wafv2_ip_set.IPBadBotSetIPV4.id
}
output "ipset_bad-bot-v6_id" {
  value = aws_wafv2_ip_set.IPBadBotSetIPV6.id
}



