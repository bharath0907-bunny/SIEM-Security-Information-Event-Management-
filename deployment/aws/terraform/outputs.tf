# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - AWS Terraform Outputs
# ==============================================================================

output "siem_server_public_ip" {
  description = "The public IP address of the Wazuh SIEM Manager instance"
  value       = aws_instance.siem_server.public_ip
}

output "siem_server_dns" {
  description = "The public DNS record of the Wazuh SIEM Manager instance"
  value       = aws_instance.siem_server.public_dns
}

output "target_server_public_ip" {
  description = "The public IP address of the monitored Ubuntu target instance"
  value       = aws_instance.linux_target.public_ip
}

output "guardduty_detector_id" {
  description = "Activated AWS GuardDuty Detector configuration ID"
  value       = aws_guardduty_detector.detector.id
}

output "cloudtrail_s3_bucket" {
  description = "The S3 Bucket name containing CloudTrail JSON event audits"
  value       = aws_s3_bucket.cloudtrail_bucket.id
}
