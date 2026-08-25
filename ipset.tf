
# Terraform owns the allow and block lists: they are configuration.
resource "aws_wafv2_ip_set" "allow_v4" {
  name               = "${local.name}-allow-v4"
  description        = "Addresses exempt from every rule"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = var.allow_ipv4
  tags               = var.tags
}

resource "aws_wafv2_ip_set" "allow_v6" {
  name               = "${local.name}-allow-v6"
  description        = "Addresses exempt from every rule"
  scope              = var.scope
  ip_address_version = "IPV6"
  addresses          = var.allow_ipv6
  tags               = var.tags
}

resource "aws_wafv2_ip_set" "block_v4" {
  name               = "${local.name}-block-v4"
  description        = "Addresses blocked outright"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = var.block_ipv4
  tags               = var.tags
}

resource "aws_wafv2_ip_set" "block_v6" {
  name               = "${local.name}-block-v6"
  description        = "Addresses blocked outright"
  scope              = var.scope
  ip_address_version = "IPV6"
  addresses          = var.block_ipv6
  tags               = var.tags
}

# An external writer owns these: a honeypot, an abuse job, an operator script.
# Terraform creates them empty and never reconciles their contents.
# ponytail: no expiry. AWS caps an IP set at 10,000 addresses and nothing here
# ages entries out, so a writer that never removes anything eventually wedges.
# Upgrade path is a scheduled job that prunes by age, which needs its own store
# because a WAF IP set carries no per-entry timestamp.
resource "aws_wafv2_ip_set" "bot_v4" {
  name               = "${local.name}-bot-v4"
  description        = "Bad bot addresses, written outside Terraform"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = []
  tags               = var.tags
  lifecycle {
    ignore_changes = [addresses]
  }
}

resource "aws_wafv2_ip_set" "bot_v6" {
  name               = "${local.name}-bot-v6"
  description        = "Bad bot addresses, written outside Terraform"
  scope              = var.scope
  ip_address_version = "IPV6"
  addresses          = []
  tags               = var.tags
  lifecycle {
    ignore_changes = [addresses]
  }
}
