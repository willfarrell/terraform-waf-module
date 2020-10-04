
# IPv4
resource "aws_wafv2_ip_set" "WhitelistSetV4" {
  name  = "${var.name}-WhitelistSetV4"
  description = "Allow whitelist for IPV4 addresses"
  scope = var.scope
  ip_address_version = "IPV4"
  addresses = []
}

resource "aws_wafv2_ip_set" "BlacklistSetIPV4" {
  name  = "${var.name}-BlacklistSetIPV4"
  description = "Block blacklist for IPV4 addresses"
  scope = var.scope
  ip_address_version = "IPV4"
  addresses = []
}

resource "aws_wafv2_ip_set" "HTTPFloodSetIPV4" {
  name  = "${var.name}-HTTPFloodSetIPV4"
  description = "Block HTTP Flood IPV4 addresses"
  scope = var.scope
  ip_address_version = "IPV4"
  addresses = []
}

resource "aws_wafv2_ip_set" "ScannersProbesSetIPV4" {
  name  = "${var.name}-ScannersProbesSetIPV4"
  description = "Block Scanners/Probes IPV4 addresses"
  scope = var.scope
  ip_address_version = "IPV4"
  addresses = []
}

resource "aws_wafv2_ip_set" "IPReputationListsSetIPV4" {
  name  = "${var.name}-IPReputationListsSetIPV4"
  description = "Block Reputation List IPV4 addresses"
  scope = var.scope
  ip_address_version = "IPV4"
  addresses = []
}

resource "aws_wafv2_ip_set" "IPBadBotSetIPV4" {
  name  = "${var.name}-IPBadBotSetIPV4"
  description = "Block Bad Bot IPV4 addresses"
  scope = var.scope
  ip_address_version = "IPV4"
  addresses = []
}

# IPv6
resource "aws_wafv2_ip_set" "WhitelistSetV6" {
  name  = "${var.name}-WhitelistSetV6"
  description = "Allow whitelist for IPV6 addresses"
  scope = var.scope
  ip_address_version = "IPV6"
  addresses = []
}

resource "aws_wafv2_ip_set" "BlacklistSetIPV6" {
  name  = "${var.name}-BlacklistSetIPV6"
  description = "Block blacklist for IPV6 addresses"
  scope = var.scope
  ip_address_version = "IPV6"
  addresses = []
}

resource "aws_wafv2_ip_set" "HTTPFloodSetIPV6" {
  name  = "${var.name}-HTTPFloodSetIPV6"
  description = "Block HTTP Flood IPV6 addresses"
  scope = var.scope
  ip_address_version = "IPV6"
  addresses = []
}

resource "aws_wafv2_ip_set" "ScannersProbesSetIPV6" {
  name  = "${var.name}-ScannersProbesSetIPV6"
  description = "Block Scanners/Probes IPV6 addresses"
  scope = var.scope
  ip_address_version = "IPV6"
  addresses = []
}

resource "aws_wafv2_ip_set" "IPReputationListsSetIPV6" {
  name  = "${var.name}-IPReputationListsSetIPV6"
  description = "Block Reputation List IPV6 addresses"
  scope = var.scope
  ip_address_version = "IPV6"
  addresses = []
}

resource "aws_wafv2_ip_set" "IPBadBotSetIPV6" {
  name  = "${var.name}-IPBadBotSetIPV6"
  description = "Block Bad Bot IPV6 addresses"
  scope = var.scope
  ip_address_version = "IPV6"
  addresses = []
}