## Blacklists

resource "aws_waf_rule" "wafBlacklistRule" {
  count = var.type != "regional" ? 1 : 0
  depends_on = [
    aws_waf_ipset.blacklist,
    aws_waf_ipset.bad-bot,
    aws_waf_ipset.scanners-probes,
    aws_waf_ipset.reputation-list,
  ]
  name        = "${local.name}wafBlacklistRule"
  metric_name = "${local.name}wafBlacklistRule"

  predicates {
    data_id = aws_waf_ipset.blacklist[0].id
    negated = false
    type    = "IPMatch"
  }

  predicates {
    data_id = aws_waf_ipset.bad-bot[0].id
    negated = false
    type    = "IPMatch"
  }

  predicates {
    data_id = aws_waf_ipset.scanners-probes[0].id
    negated = false
    type    = "IPMatch"
  }

  predicates {
    data_id = aws_waf_ipset.reputation-list[0].id
    negated = false
    type    = "IPMatch"
  }
}

resource "aws_waf_ipset" "blacklist" {
  count = var.type != "regional" ? 1 : 0
  name  = "${var.name}-blacklist-ipset"
}

resource "aws_waf_ipset" "bad-bot" {
  count = var.type != "regional" ? 1 : 0
  name  = "${var.name}-bad-bot-ipset"
}

resource "aws_waf_ipset" "scanners-probes" {
  count = var.type != "regional" ? 1 : 0
  name  = "${var.name}-scanners-probes-ipset"
}

resource "aws_waf_ipset" "reputation-list" {
  count = var.type != "regional" ? 1 : 0
  name  = "${var.name}-reputation-list-ipset"
}

# Regional
resource "aws_wafregional_rule" "wafBlacklistRule" {
  count = var.type == "regional" ? 1 : 0
  depends_on = [
    aws_wafregional_ipset.blacklist,
    aws_wafregional_ipset.bad-bot,
    aws_wafregional_ipset.scanners-probes,
    aws_wafregional_ipset.reputation-list,
  ]
  name        = "${local.name}wafBlacklistRule"
  metric_name = "${local.name}wafBlacklistRule"

  predicate {
    data_id = aws_wafregional_ipset.blacklist[0].id
    negated = false
    type    = "IPMatch"
  }

  predicate {
    data_id = aws_wafregional_ipset.bad-bot[0].id
    negated = false
    type    = "IPMatch"
  }

  predicate {
    data_id = aws_wafregional_ipset.scanners-probes[0].id
    negated = false
    type    = "IPMatch"
  }

  predicate {
    data_id = aws_wafregional_ipset.reputation-list[0].id
    negated = false
    type    = "IPMatch"
  }
}

resource "aws_wafregional_ipset" "blacklist" {
  count = var.type == "regional" ? 1 : 0
  name  = "${var.name}-blacklist-ipset"
}

resource "aws_wafregional_ipset" "bad-bot" {
  count = var.type == "regional" ? 1 : 0
  name  = "${var.name}-bad-bot-ipset"
}

resource "aws_wafregional_ipset" "scanners-probes" {
  count = var.type == "regional" ? 1 : 0
  name  = "${var.name}-scanners-probes-ipset"
}

resource "aws_wafregional_ipset" "reputation-list" {
  count = var.type == "regional" ? 1 : 0
  name  = "${var.name}-reputation-list-ipset"
}

