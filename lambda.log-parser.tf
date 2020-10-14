data "aws_iam_policy_document" "log-parser" {
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

resource "aws_iam_policy" "log-parser" {
  name   = "${local.name}-waf-log-parser-policy"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid":"LogsAccess",
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

resource "aws_iam_role" "log-parser" {
  name = "${local.name}-waf-log-parser"
  assume_role_policy = data.aws_iam_policy_document.log-parser.json
}

resource "aws_iam_role_policy_attachment" "log-parser" {
  role = aws_iam_role.log-parser.name
  policy_arn = aws_iam_policy.log-parser.arn
}

resource "aws_iam_policy" "scanners-probes" {
  count = var.scannersProbesProtectionActivated ? 1 : 0
  name = "${local.name}-waf-scanners-probes-policy"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid":"S3AccessGet",
      "Action": "s3:GetObject",
      "Resource": [
          "arn:aws:s3:::${local.logging_bucket}/*"
      ],
      "Effect": "Allow"
    },
    {
      "Sid":"S3AccessPut",
      "Action": "s3:PutObject",
      "Resource": [
          "arn:aws:s3:::${local.logging_bucket}/${local.name}-app_log_out.json",
          "arn:aws:s3:::${local.logging_bucket}/${local.name}-app_log_conf.json"
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
          "${aws_wafv2_ip_set.ScannersProbesSetIPV4.arn}",
          "${aws_wafv2_ip_set.ScannersProbesSetIPV6.arn}"
      ],
      "Effect": "Allow"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "scanners-probes" {
  count = var.scannersProbesProtectionActivated ? 1 : 0
  role = aws_iam_role.log-parser.name
  policy_arn = aws_iam_policy.scanners-probes[0].arn
}

resource "aws_iam_policy" "http-flood" {
  count = var.httpFloodProtectionLogParserActivated ? 1 : 0
  name = "${local.name}-waf-http-flood-policy"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid":"S3AccessGet",
      "Action": "s3:GetObject",
      "Resource": [
          "arn:aws:s3:::${local.logging_bucket}/*"
      ],
      "Effect": "Allow"
    },
    {
      "Sid":"S3AccessPut",
      "Action": "s3:PutObject",
      "Resource": [
          "arn:aws:s3:::${local.logging_bucket}/${local.name}-waf_log_out.json",
          "arn:aws:s3:::${local.logging_bucket}/${local.name}-waf_log_conf.json"
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
          "${aws_wafv2_ip_set.HTTPFloodSetIPV4.arn}",
          "${aws_wafv2_ip_set.HTTPFloodSetIPV6.arn}"
      ],
      "Effect": "Allow"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "http-flood" {
  count = var.httpFloodProtectionLogParserActivated ? 1 : 0
  role = aws_iam_role.log-parser.name
  policy_arn = aws_iam_policy.http-flood[0].arn
}

resource "aws_lambda_function" "log-parser" {
  function_name = "${local.name}-waf-log-parser"
  filename = "${path.module}/lambda/log_parser.zip"

  source_code_hash = filebase64sha256("${path.module}/lambda/log_parser.zip")
  role = aws_iam_role.log-parser.arn
  handler = "log-parser.lambda_handler"
  runtime = "python3.8"
  memory_size = 512
  timeout = 300
  publish = true
  environment {
    variables = {
      STACK_NAME = local.name
      SCOPE = var.scope
      APP_ACCESS_LOG_BUCKET = local.logging_bucket
      WAF_ACCESS_LOG_BUCKET = local.logging_bucket
      IP_SET_NAME_HTTP_FLOODV4 = "${var.name}-HTTPFloodSetIPV4"
      IP_SET_NAME_HTTP_FLOODV6 = "${var.name}-HTTPFloodSetIPV6"
      IP_SET_ID_HTTP_FLOODV4 = aws_wafv2_ip_set.HTTPFloodSetIPV4.arn
      IP_SET_ID_HTTP_FLOODV6 = aws_wafv2_ip_set.HTTPFloodSetIPV6.arn
      IP_SET_NAME_SCANNERS_PROBESV4 = "${var.name}-ScannersProbesSetIPV4"
      IP_SET_NAME_SCANNERS_PROBESV6 = "${var.name}-ScannersProbesSetIPV6"
      IP_SET_ID_SCANNERS_PROBESV4 = aws_wafv2_ip_set.ScannersProbesSetIPV4.arn
      IP_SET_ID_SCANNERS_PROBESV6 = aws_wafv2_ip_set.ScannersProbesSetIPV6.arn
      LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION = 10000
      LOG_LEVEL = "INFO"
      LOG_TYPE = "cloudfront"
      MAX_AGE_TO_UPDATE = 30
      METRIC_NAME_PREFIX = "${local.name}-waf"
      REGION = local.region
    }
  }
}

resource "aws_cloudwatch_log_group" "log-parser" {
  name              = "/aws/lambda/${local.name}-waf-log-parser"
  retention_in_days = 30
}

//resource "aws_lambda_permission" "log-parser" {
//  statement_id = "AllowExecutionFromS3Bucket"
//  action = "lambda:InvokeFunction"
//  function_name = aws_lambda_function.log-parser.function_name
//  principal = "s3.amazonaws.com"
//  source_arn = "arn:aws:s3:::${local.logging_bucket}"
//}

# Prevents other events, rework in future
resource "aws_s3_bucket_notification" "log-parser" {
  bucket = local.logging_bucket

  topic {
    #lambda_function_arn = aws_lambda_function.log-parser.arn
    topic_arn = aws_sns_topic.log-parser.arn
    events = [
      "s3:ObjectCreated:*",
    ]
    filter_prefix = "AWSLogs/${local.account_id}/CloudFront/"
    filter_suffix = ".gz"
  }

  topic {
    topic_arn = aws_sns_topic.log-parser.arn
    events = [
      "s3:ObjectCreated:*",
    ]
    filter_prefix = "AWSLogs/${local.account_id}/ALB/"
    filter_suffix = ".gz"
  }

  topic {
    topic_arn = aws_sns_topic.log-parser.arn
    events = [
      "s3:ObjectCreated:*",
    ]
    filter_prefix = "AWSLogs/${local.account_id}/WAF/"
    filter_suffix = ".gz"
  }
}

// TODO make SNS encrypted
// TODO test lambda parses event properly **
resource "aws_sns_topic" "log-parser" {
  name = "${local.name}-waf-log-parser-topic"
  #kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "log-parser" {
  arn = aws_sns_topic.log-parser.arn
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Default",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "sns:Publish",
        "sns:RemovePermission",
        "sns:SetTopicAttributes",
        "sns:DeleteTopic",
        "sns:ListSubscriptionsByTopic",
        "sns:GetTopicAttributes",
        "sns:Receive",
        "sns:AddPermission",
        "sns:Subscribe"
      ],
      "Resource": "${aws_sns_topic.log-parser.arn}"
    },
    {
      "Effect": "Allow",
      "Principal": {"AWS":"*"},
      "Action": "sns:Publish",
      "Resource": "${aws_sns_topic.log-parser.arn}",
      "Condition": {
        "ArnEquals": { "aws:SourceArn": "${local.logging_bucket}" }
      }
    }
  ]
}
POLICY
}

resource "aws_sns_topic_subscription" "log-parser" {
  topic_arn = aws_sns_topic.log-parser.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.log-parser.arn
}

# TODO don't update file if already exists
resource "aws_s3_bucket_object" "app-log-parser" {
  bucket = local.logging_bucket
  key = "/${local.name}-app_log_conf.json"
  content = <<JSON
{
    "general": {
        "errorThreshold": ${var.errorThreshold},
        "blockPeriod": ${var.blockPeriod},
        "errorCodes": ["400", "401", "403", "404", "405"]
    },
    "uriList": {}
}
JSON

}

resource "aws_s3_bucket_object" "waf-log-parser" {
bucket  = local.logging_bucket
key     = "/${local.name}-waf_log_conf.json"
content = <<JSON
{
    "general": {
        "errorThreshold": ${var.errorThreshold},
        "blockPeriod": ${var.blockPeriod},
        "ignoredSufixes": []
    },
    "uriList": {}
}
JSON

}

