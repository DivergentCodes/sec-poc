###########################################################
# Local variables
###########################################################

locals {
  ssh_key_path = "${path.module}/ssh"
  ubuntu24_amd_ami = {
    # https://cloud-images.ubuntu.com/locator/ec2/
    us-east-1 = "ami-0cad6ee50670e3d0e"
    us-east-2 = "ami-0c995fbcf99222492"
    us-west-1 = "ami-0a1d34394ed12ff2a"
    us-west-2 = "ami-01a8b7cc84780badb"
  }
  ami_id = local.ubuntu24_amd_ami[var.region]
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
  key_name   = "deployer-key-ed25519"
  public_key = tls_private_key.ssh_key_ed25519.public_key_openssh
}
