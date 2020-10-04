variable "name" {
  description = "unique prefix for names. alpha numeric only. ie uatAppname"
  default     = ""
}

variable "scope" {
  type    = string // CLOUDFRONT, REGIONAL
}

variable "defaultAction" {
  default = "DENY"
}

variable "requestThreshold" {
  description = "If you chose yes for the Activate HTTP Flood Protection parameter, enter the maximum acceptable requests per FIVE-minute period per IP address. Please note that AWS WAF rate based rule requires values greather than 2,000 (if you chose Lambda/Athena log parser options, you can use any value greather than zero). If you chose to deactivate this protection, ignore this parameter. Default to `2000`, min allowed: `2000`"
  type        = number
  default     = 100
}

variable "excluded_rules" {
  type = list(string)
  default = []
}

//variable "rules" {
//  type = list(map)
//  default = []
//}

variable "logging_bucket" {
  description = ""
  default     = ""
}

