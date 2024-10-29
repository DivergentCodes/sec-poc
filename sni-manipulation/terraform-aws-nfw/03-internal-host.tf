###############################################################################
# Internal host instance.
###############################################################################

# VM for internal host instance.
resource "aws_instance" "internal_instance" {
  instance_type = var.instance_type
  ami           = data.aws_ami.al2023.id
  key_name      = aws_key_pair.deployer_ed25519.key_name
  subnet_id     = aws_subnet.private.id

  user_data_replace_on_change = true

  vpc_security_group_ids = [aws_security_group.internal_instance.id]

  metadata_options {
    # Whether the IMDS is enabled.
    http_endpoint = "enabled"
    # Force IMDSv2 to prevent SSRF.
    http_tokens   = "required"
  }

  tags = {
    Name = "${var.project_name}-internal-instance-subnet-az${var.availability_zone}"
  }

  depends_on = [ aws_security_group.internal_instance ]
}

###############################################################################
# Security group for internal instance.
###############################################################################

resource "aws_security_group" "internal_instance" {
  vpc_id = aws_vpc.main.id

  name        = "${var.project_name}-internal-instance-az${var.availability_zone}-${random_id.instance.id}"
  description = "Internal network interface on the private network subnet."

  tags = {
    Name = "${var.project_name}-internal-instance-az${var.availability_zone}-${random_id.instance.id}"
  }
}

resource "aws_vpc_security_group_ingress_rule" "internal_private_nic_inbound_vpc" {
  security_group_id = aws_security_group.internal_instance.id
  description       = "Allow all inbound from VPC"

  cidr_ipv4   = aws_vpc.main.cidr_block
  ip_protocol = "-1"

  tags = {
    Name = "${var.project_name}-internal-all-inbound-vpc"
  }
}

resource "aws_vpc_security_group_ingress_rule" "internal_private_nic_inbound_admin" {
  security_group_id = aws_security_group.internal_instance.id
  description       = "Allow all inbound from admin IP"

  cidr_ipv4   = var.admin_ip
  ip_protocol = "-1"

  tags = {
    Name = "${var.project_name}-internal-all-inbound-admin"
  }
}

resource "aws_vpc_security_group_egress_rule" "internal_private_nic_all_outbound" {
  security_group_id = aws_security_group.internal_instance.id
  description       = "Allow all outbound"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "-1"

  tags = {
    Name = "${var.project_name}-internal-all-outbound"
  }
}

###########################################################
# SSH login script to internal instance
###########################################################

resource "local_file" "internal_login" {
  content = <<-EOF
#!/bin/bash
ssh -i ${local.ssh_key_path}/id_ed25519 \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ProxyCommand="ssh -i ${local.ssh_key_path}/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -W %h:%p ${local.ami_user}@${aws_instance.jumpbox_instance.public_ip}" \
    ${local.ami_user}@${aws_instance.internal_instance.private_ip}
EOF
  filename = "${local.script_path}/internal-login.sh"
  file_permission = "0755"
}

resource "local_file" "internal_client_upload" {
  content = <<-EOF
#!/bin/bash
scp -i ${local.ssh_key_path}/id_ed25519 \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ProxyCommand="ssh -i ${local.ssh_key_path}/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -W %h:%p ${local.ami_user}@${aws_instance.jumpbox_instance.public_ip}" \
    ../dist/client-linux-amd64 \
    ${local.ami_user}@${aws_instance.internal_instance.private_ip}:/home/${local.ami_user}/client
EOF
  filename = "${local.script_path}/internal-client-upload.sh"
  file_permission = "0755"
}
