resource "aws_waf_web_acl" "wafOwaspACL" {
  count = var.type != "regional" ? 1 : 0
  depends_on = [
    aws_waf_rate_based_rule.wafHTTPFloodRule,
    aws_waf_rule.wafSQLInjectionRule,
    aws_waf_rule.wafXSSRule,
    aws_waf_rule.wafAdminAccessRule,
    aws_waf_rule.wafAuthTokenRule,
    aws_waf_rule.wafCSRFRule,
    aws_waf_rule.wafPathsRule,
    aws_waf_rule.wafServerSideIncludeRule,
    aws_waf_rule.wafBlacklistRule,
    aws_waf_rule.wafWhitelistRule,
    aws_waf_rule.wafServerSideIncludeRule,
    aws_waf_rule.wafAdminAccessRule,
  ]

  name        = "${local.name}wafOwaspACL"
  metric_name = "${local.name}wafOwaspACL"

  default_action {
    type = var.defaultAction
  }

  # Max 10 Rules - https://docs.aws.amazon.com/waf/latest/developerguide/limits.html
  rules {
    action {
      type = "BLOCK"
    }

    priority = 1
    rule_id  = aws_waf_rule.wafBlacklistRule.id
  }

  // Breaks ACL :( TODO fix, manual attach
  //  rules {
  //    action {
  //      type = "BLOCK"
  //    }
  //
  //    priority = 2
  //    rule_id  = "${aws_waf_rate_based_rule.wafHTTPFloodRule.id}"
  //  }

  rules {
    action {
      type = "BLOCK"
    }

    priority = 3
    rule_id  = aws_waf_rule.wafSizeRestrictionRule.id
  }

  rules {
    action {
      type = "BLOCK"
    }

    priority = 4
    rule_id  = aws_waf_rule.wafAuthTokenRule.id
  }

  rules {
    action {
      type = "BLOCK"
    }

    priority = 5
    rule_id  = aws_waf_rule.wafSQLInjectionRule.id
  }

  rules {
    action {
      type = "BLOCK"
    }

    priority = 6
    rule_id  = aws_waf_rule.wafXSSRule.id
  }

  rules {
    action {
      type = "BLOCK"
    }

    priority = 7
    rule_id  = aws_waf_rule.wafPathsRule.id
  }

  rules {
    action {
      type = "BLOCK"
    }

    priority = 8
    rule_id  = aws_waf_rule.wafCSRFRule.id
  }

  //  rules {
  //    action {
  //      type = "BLOCK"
  //    }
  //
  //    priority = 9
  //    rule_id  = "${aws_waf_rule.wafServerSideIncludeRule.id}"
  //  }

  //  rules {
  //    action {
  //      type = "BLOCK"
  //    }
  //
  //    priority = 10
  //    rule_id  = "${aws_waf_rule.wafAdminAccessRule.id}"
  //  }

  rules {
    action {
      type = "ALLOW"
    }

    priority = 10
    rule_id  = aws_waf_rule.wafWhitelistRule.id
  }

  logging_configuration {
    log_destination = aws_kinesis_firehose_delivery_stream.logging.arn
    // TODO redacte `password`, `mfa/otp`, tokens
    //redacted_fields = {}
  }
}

resource "aws_wafregional_web_acl" "wafrOwaspACL" {
  count = var.type == "regional" ? 1 : 0
  depends_on = [
    aws_wafregional_rate_based_rule.wafHTTPFloodRule,
    aws_wafregional_rule.wafSQLInjectionRule,
    aws_wafregional_rule.wafXSSRule,
    aws_wafregional_rule.wafAdminAccessRule,
    aws_wafregional_rule.wafAuthTokenRule,
    aws_wafregional_rule.wafCSRFRule,
    aws_wafregional_rule.wafPathsRule,
    aws_wafregional_rule.wafServerSideIncludeRule,
    aws_wafregional_rule.wafBlacklistRule,
    aws_wafregional_rule.wafWhitelistRule,
    aws_wafregional_rule.wafServerSideIncludeRule,
    aws_wafregional_rule.wafAdminAccessRule,
  ]

  name        = "${local.name}wafrOwaspACL"
  metric_name = "${local.name}wafrOwaspACL"

  default_action {
    type = var.defaultAction
  }

  rule {
    action {
      type = "BLOCK"
    }

    priority = 1
    rule_id  = aws_wafregional_rule.wafBlacklistRule.id
  }

  // Breaks ACL :( TODO fix, manual attach
  //  rule {
  //    action {
  //      type = "BLOCK"
  //    }
  //
  //    priority = 2
  //    rule_id  = "${aws_wafregional_rate_based_rule.wafHTTPFloodRule.id}"
  //  }

  rule {
    action {
      type = "BLOCK"
    }

    priority = 3
    rule_id  = aws_wafregional_rule.wafSizeRestrictionRule.id
  }

  rule {
    action {
      type = "BLOCK"
    }

    priority = 4
    rule_id  = aws_waf_rule.wafAuthTokenRule.id
  }

  rule {
    action {
      type = "BLOCK"
    }

    priority = 5
    rule_id  = aws_wafregional_rule.wafSQLInjectionRule.id
  }

  rule {
    action {
      type = "BLOCK"
    }

    priority = 6
    rule_id  = aws_wafregional_rule.wafXSSRule.id
  }

  rule {
    action {
      type = "BLOCK"
    }

    priority = 7
    rule_id  = aws_wafregional_rule.wafPathsRule.id
  }

  rule {
    action {
      type = "BLOCK"
    }

    priority = 8
    rule_id  = aws_wafregional_rule.wafCSRFRule.id
  }

  //  rule {
  //    action {
  //      type = "BLOCK"
  //    }
  //
  //    priority = 9
  //    rule_id  = "${aws_wafregional_rule.wafServerSideIncludeRule.id}"
  //  }

  //  rule {
  //    action {
  //      type = "BLOCK"
  //    }
  //
  //    priority = 10
  //    rule_id  = "${aws_wafregional_rule.wafAdminAccessRule.id}"
  //  }

  rule {
    action {
      type = "ALLOW"
    }

    priority = 10
    rule_id  = aws_wafregional_rule.wafWhitelistRule.id
  }

  logging_configuration {
    log_destination = aws_kinesis_firehose_delivery_stream.logging.arn
    // TODO redacte `password`, `mfa/otp`, tokens
    //redacted_fields = {}
  }
}

resource "aws_kinesis_firehose_delivery_stream" "logging" {
  name        = "aws-waf-logs-${local.name}"
  destination = "s3"

  s3_configuration {
    role_arn   = aws_iam_role.logging.arn
    bucket_arn = "arn:aws:s3:::${local.logging_bucket}"
    prefix     = "/AWSLogs/${local.account_id}/WAF/${local.region}/"
  }
}

resource "aws_iam_role" "logging" {
  name = "${local.name}-waf-stream-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "firehose.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

}

resource "aws_iam_policy" "logging" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid":"CloudWatchAccess",
      "Action": [
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/kinesisfirehose/${local.name}-waf-stream:*"
      ],
      "Effect": "Allow"
    },
    {
      "Sid":"KinesisAccess",
      "Action": [
        "kinesis:DescribeStream",
        "kinesis:GetShardIterator",
        "kinesis:GetRecords"
      ],
      "Resource": [
        "${aws_kinesis_firehose_delivery_stream.logging.arn}"
      ],
      "Effect": "Allow"
    },
    {
      "Sid":"S3Access",
      "Action": [
        "s3:AbortMultipartUpload",
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:ListBucketMultipartUploads",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::${local.logging_bucket}",
        "arn:aws:s3:::${local.logging_bucket}/*"
      ],
      "Effect": "Allow"
    }
  ]
}
POLICY

}

resource "aws_iam_role_policy_attachment" "logging" {
role       = aws_iam_role.logging.name
policy_arn = aws_iam_policy.logging.arn
}

