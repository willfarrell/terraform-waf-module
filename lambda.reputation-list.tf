data "aws_iam_policy_document" "reputation-list" {
  count = var.reputationListsProtectionActivated ? 1 : 0
  statement {
    actions = [
      "sts:AssumeRole",
    ]

    principals {
      type = "Service"

      identifiers = [
        "lambda.amazonaws.com",
      ]
    }
  }
}

/*
The wrong arn is returned for IPsets
Expected: arn:aws:wafv2:us-east-1:{account_id}:global/ipset/{ip_set_id}/{ip_set_id}
Actual: arn:aws:wafv2:us-east-1:{account_id}:global/ipset/{ip_set_name}/{ip_set_id}

*/
resource "aws_iam_policy" "reputation-list" {
  count = var.reputationListsProtectionActivated ? 1 : 0
  name   = "${local.name}-waf-reputation-list-policy"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid":"CloudWatchLogs",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/*"
      ],
      "Effect": "Allow"
    },
    {
      "Sid":"WAFGetAndUpdateIPSet",
      "Action": [
          "wafv2:GetIPSet",
          "wafv2:UpdateIPSet"
      ],
      "Resource": [
          "${aws_wafv2_ip_set.IPReputationListsSetIPV4.arn}",
          "${aws_wafv2_ip_set.IPReputationListsSetIPV6.arn}"
      ],
      "Effect": "Allow"
    },
    {
      "Sid":"CloudWatchAccess",
      "Action": "cloudwatch:GetMetricStatistics",
      "Resource": [
        "*"
      ],
      "Effect": "Allow"
    }
  ]
}
POLICY
}

resource "aws_iam_role" "reputation-list" {
  count = var.reputationListsProtectionActivated ? 1 : 0
  name = "${local.name}-waf-reputation-list"
  assume_role_policy = data.aws_iam_policy_document.reputation-list[0].json
}

resource "aws_iam_role_policy_attachment" "reputation-list" {
  count = var.reputationListsProtectionActivated ? 1 : 0
  role = aws_iam_role.reputation-list[0].name
  policy_arn = aws_iam_policy.reputation-list[0].arn
}

resource "aws_iam_role_policy_attachment" "reputation-list-dlq" {
  count = var.reputationListsProtectionActivated ? 1 : 0
  role = aws_iam_role.reputation-list[0].name
  policy_arn = var.dead_letter_policy_arn
}

resource "aws_lambda_function" "reputation-list" {
  count = var.reputationListsProtectionActivated ? 1 : 0
  function_name = "${local.name}-waf-reputation-list"
  filename = "${path.module}/lambda/reputation_lists_parser.zip"

  source_code_hash = filebase64sha256("${path.module}/lambda/reputation_lists_parser.zip")
  role = aws_iam_role.reputation-list[0].arn
  handler = "reputation-lists.lambda_handler"
  runtime = "python3.9"
  memory_size = 512
  timeout = 300
  publish = true

  dead_letter_config {
    target_arn = var.dead_letter_arn
  }

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      STACK_NAME = local.name
      SCOPE = var.scope
      IP_SET_NAME_REPUTATIONV4 = "${var.name}-IPReputationListsSetIPV4"
      IP_SET_NAME_REPUTATIONV6 = "${var.name}-IPReputationListsSetIPV6"
      IP_SET_ID_REPUTATIONV4 = aws_wafv2_ip_set.IPReputationListsSetIPV4.arn
      IP_SET_ID_REPUTATIONV6 = aws_wafv2_ip_set.IPReputationListsSetIPV6.arn
      LOG_TYPE = "cloudfront"
      LOG_LEVEL = "INFO"
      IPREPUTATIONLIST_METRICNAME = "IPReputationList"
      METRIC_NAME_PREFIX = "${local.name}-waf"
      URL_LIST: "[{\"url\":\"https://www.spamhaus.org/drop/drop.txt\"},{\"url\":\"https://www.spamhaus.org/drop/edrop.txt\"},{\"url\":\"https://check.torproject.org/exit-addresses\", \"prefix\":\"ExitAddress\"},{\"url\":\"https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt\"}]"
    }
  }
}

resource "aws_cloudwatch_log_group" "reputation-list" {
  count = var.reputationListsProtectionActivated ? 1 : 0
  name              = "/aws/lambda/${local.name}-waf-reputation-list"
  retention_in_days = 30
}

## Event Trigger
resource "aws_cloudwatch_event_rule" "reputation-list" {
  count = var.reputationListsProtectionActivated ? 1 : 0
  name = "${local.name}-waf-reputation-list-event"
  description = "hourly"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "reputation-list" {
  count = var.reputationListsProtectionActivated ? 1 : 0
  rule = aws_cloudwatch_event_rule.reputation-list[0].name
  arn = aws_lambda_function.reputation-list[0].arn
}

resource "aws_lambda_permission" "reputation-list" {
  count = var.reputationListsProtectionActivated ? 1 : 0
  statement_id  = "${local.name}-waf-reputation-list-event"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.reputation-list[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.reputation-list[0].arn
}

