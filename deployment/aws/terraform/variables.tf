# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - AWS Terraform Variables
# ==============================================================================

variable "aws_region" {
  description = "The target AWS Region for all resource configurations"
  type        = string
  default     = "us-east-1"
}

variable "ubuntu_ami" {
  description = "The target Ubuntu Server LTS AMI ID"
  type        = string
  default     = "ami-0c7217cdde317cfec" # Standard Ubuntu 22.04 LTS HVM in us-east-1 (changes occasionally)
}

variable "key_pair_name" {
  description = "Target SSH key pair name configured on AWS console for node access"
  type        = string
  default     = "siem-lab-key"
}

variable "admin_ip_cidr" {
  description = "Allowed IP range for SIEM SSH/HTTPS dashboards console management (restrict to your IP)"
  type        = string
  default     = "0.0.0.0/0" # WARNING: Open globally for simulation lab. Tighten for production.
}

variable "cloudtrail_s3_bucket_name" {
  description = "Globally unique name for AWS CloudTrail log storage S3 Bucket"
  type        = string
  default     = "siem-platform-cloudtrail-logs-unique-bucket-12345"
}
