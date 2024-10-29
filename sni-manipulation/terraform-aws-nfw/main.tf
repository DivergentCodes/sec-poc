###########################################################
# Local variables
###########################################################

locals {
  script_path  = "${path.module}/scripts"
  ssh_key_path = "${path.module}/ssh"
  ami_user     = "ec2-user"
}

resource "random_id" "instance" {
  keepers = {
    # Generate a new ID each time project_name changes.
    project_name = var.project_name
  }

  byte_length = 8
}

###############################################################################
# Amazon Linux 2023 AMI for NAT instance.
###############################################################################

data "aws_ami" "al2023" {

  owners      = ["amazon"]
  most_recent = true

  filter {
    name   = "name"
    values = ["al2023-ami-minimal-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

###########################################################
# SSH Key Generation
###########################################################

resource "tls_private_key" "ssh_key_ed25519" {
  algorithm = "ED25519"
}

resource "local_file" "private_key" {
  content         = tls_private_key.ssh_key_ed25519.private_key_openssh
  filename        = "${path.module}/ssh/id_ed25519"
  file_permission = "0600"
}

resource "local_file" "public_key" {
  content         = tls_private_key.ssh_key_ed25519.public_key_openssh
  filename        = "${path.module}/ssh/id_ed25519.pub"
  file_permission = "0644"
}

resource "aws_key_pair" "deployer_ed25519" {
  key_name   = "${var.project_name}-ed25519"
  public_key = tls_private_key.ssh_key_ed25519.public_key_openssh
}
