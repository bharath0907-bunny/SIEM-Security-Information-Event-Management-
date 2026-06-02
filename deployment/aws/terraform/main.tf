# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - AWS Cloud Lab Terraform
# ==============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# 1. Isolated Virtual Private Cloud (VPC)
resource "aws_vpc" "siem_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "SIEM-Lab-VPC"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.siem_vpc.id

  tags = {
    Name = "SIEM-Lab-IGW"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.siem_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "SIEM-Lab-PublicSubnet"
  }
}

resource "aws_route_table" "route_table" {
  vpc_id = aws_vpc.siem_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "SIEM-Lab-RouteTable"
  }
}

resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.route_table.id
}

# 2. Security Group mapping firewall ports
resource "aws_security_group" "siem_sg" {
  name        = "siem_platform_security_group"
  description = "Allows Wazuh agent pairing, Syslog ingestion, HTTPS Kibana dashboards, and SSH administration"
  vpc_id      = aws_vpc.siem_vpc.id

  # SSH Administration access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip_cidr]
  }

  # Wazuh Dashboard (HTTPS)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip_cidr]
  }

  # Wazuh Agent Registration Port
  ingress {
    from_port   = 1515
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Wazuh Agent Communication Port
  ingress {
    from_port   = 1514
    to_port     = 1514
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Logstash / Syslog UDP Ingestion Port
  ingress {
    from_port   = 514
    to_port     = 514
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Outbound Allow All
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SIEM-Lab-SecurityGroup"
  }
}

# 3. AWS EC2 VM Instance hosting the Wazuh SIEM Manager
resource "aws_instance" "siem_server" {
  ami                    = var.ubuntu_ami
  instance_type          = "t3.medium" # Minimum recommended resources (2 vCPUs, 4GB RAM)
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.siem_sg.id]
  key_name               = var.key_pair_name

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name = "SIEM-Wazuh-Manager-Server"
  }
}

# 4. AWS EC2 VM Target Instance representing Monitored Client Node
resource "aws_instance" "linux_target" {
  ami                    = var.ubuntu_ami
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.siem_sg.id]
  key_name               = var.key_pair_name

  tags = {
    Name = "SIEM-Monitored-Ubuntu-Target"
  }
}

# 5. AWS CloudTrail Configuration (Audit Trail logging to S3)
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = var.cloudtrail_s3_bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${var.cloudtrail_s3_bucket_name}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${var.cloudtrail_s3_bucket_name}/AWSLogs/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}

resource "aws_cloudtrail" "siem_trail" {
  name                          = "siem-platform-audit-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.cloudtrail_policy]
}

# 6. Enable AWS GuardDuty for Threat Intelligence
resource "aws_guardduty_detector" "detector" {
  enable = true
}
