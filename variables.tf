variable "name" {
  description = "unique prefix for names. alpha numeric only. ie uatAppname"
  default     = ""
}

variable "scope" {
  type    = string // CLOUDFRONT, REGIONAL
}

variable "defaultAction" {
  default = "block"
}

variable "requestThreshold" {
  description = "If you chose yes for the Activate HTTP Flood Protection parameter, enter the maximum acceptable requests per FIVE-minute period per IP address. Please note that AWS WAF rate based rule requires values greather than 2,000 (if you chose Lambda/Athena log parser options, you can use any value greather than zero). If you chose to deactivate this protection, ignore this parameter. Default to `2000`, min allowed: `2000`"
  type        = number
  default     = 2000
}

variable "errorThreshold" {
  description = "If you chose yes for the Activate Scanners & Probes Protection parameter, enter the maximum acceptable bad requests per minute per IP. If you chose to deactivate this protection protection, ignore this parameter."
  type = number
  default = 50
}

variable "blockPeriod" {
  description = "If you chose yes for the Activate Scanners & Probes Protection or HTTP Flood Lambda/Athena log parser parameters, enter the period (in minutes) to block applicable IP addresses. If you chose to deactivate log parsing, ignore this parameter."
  type        = number
  default     = 240
}

variable "excluded_rules" {
  type = list(string)
  default = []
}

//variable "rules" {
//  type = list(map)
//  default = []
//}

variable "uploadToS3Activated" {
  type = bool
  default = false
}

variable "uploadToS3Path" {
  type = string
  description = "path that upload will take place"
  default = ""
}

variable "whitelistActivated" {
  type = bool
  default = false
}

variable "blacklistProtectionActivated" {
  type = bool
  default = true
}

variable "httpFloodProtectionLogParserActivated" {
  type = bool
  default = true
}

variable "scannersProbesProtectionActivated" {
  type = bool
  default = true
}

variable "reputationListsProtectionActivated" {
  type = bool
  default = true
}

variable "badBotProtectionActivated" {
  type = bool
  default = true
}

variable "SqlInjectionProtectionSensitivityLevelParam" {
  type = string
  description = "Sensitivity Level for SQL Injection Protection. LOW or HIGH"
  default = "LOW"
}

variable "logging_bucket" {
  description = ""
  default     = ""
}

variable "dead_letter_arn" {
  type = string
}

variable "dead_letter_policy_arn" {
  type = string
}

variable "kms_master_key_id" {
  type = string
  default = null
}

