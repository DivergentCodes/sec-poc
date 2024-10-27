variable "project_name" {
  description = "The slug name of the project"
  type        = string
  default     = "sni-manipulation-poc"
}

variable "region" {
  description = "The AWS region to deploy to"
  type        = string
  default     = "us-east-1"
}

variable "availability_zone" {
  description = "The AWS availability zone within the region"
  type        = string
  default     = "a"
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "The CIDR block for the public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "The CIDR block for the private subnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "admin_ip" {
  description = "The IP address allowed for SSH access"
  type        = string
}

variable "instance_type" {
  description = "The instance type for EC2 instances"
  type        = string
  default     = "t3.nano"
}

variable "additional_nat_instance_security_group_ids" {
  description = "Additional security groups for the NAT instance."
  type        = list(string)
  default     = []
}

variable "enable_egress_web_filtering" {
  description = "Enable HTTP web filtering via Squid proxy (NAT Instance only)."
  type        = bool
  default     = false
}

variable "allowed_egress_web_domains" {
  description = "Domains that are allowed through HTTP(S) filtering."
  type        = list(string)
  default     = [
    ".amazonaws.com",
    ".ubuntu.com",
    "api.snapcraft.io",
  ]
}
