###############################################################################
# Jumpbox instance.
###############################################################################

# VM for jumpbox instance.
resource "aws_instance" "jumpbox_instance" {
  instance_type = var.instance_type
  ami           = data.aws_ami.al2023.id
  key_name      = aws_key_pair.deployer_ed25519.key_name
  subnet_id     = aws_subnet.public.id

  # Find user-data.txt after boot:
  #   sudo cat /var/lib/cloud/instances/*/user-data.txt
  user_data = templatefile(
    "${local.script_path}/user_data_jumpbox_instance_centos.sh",
    {
      allowed_egress_web_domains  = join("\n", var.allowed_egress_web_domains)
    }
  )

  user_data_replace_on_change = true

  # Disable source destination checking for the ENI.
  # https://docs.aws.amazon.com/vpc/latest/userguide/VPC_NAT_Instance.html#EIP_Disable_SrcDestCheck
  source_dest_check = false

  vpc_security_group_ids = toset(flatten([
    aws_security_group.jumpbox_instance.id,
  ]))

  metadata_options {
    # Whether the IMDS is enabled.
    http_endpoint = "enabled"
    # Force IMDSv2 to prevent SSRF.
    http_tokens   = "required"
  }

  tags = {
    Name = "${var.project_name}-jumpbox-instance-subnet-az${var.availability_zone}"
  }

  depends_on = [ aws_security_group.jumpbox_instance ]
}

###############################################################################
# Security group for jumpbox instance.
###############################################################################

resource "aws_security_group" "jumpbox_instance" {
  vpc_id = aws_vpc.main.id

  name        = "${var.project_name}-jumpbox-instance-az${var.availability_zone}-${random_id.instance.id}"
  description = "Jumpbox network interface on the public network subnet."

  tags = {
    Name = "${var.project_name}-jumpbox-instance-az${var.availability_zone}-${random_id.instance.id}"
  }
}

resource "aws_vpc_security_group_ingress_rule" "jumpbox_public_nic_inbound_vpc" {
  security_group_id = aws_security_group.jumpbox_instance.id
  description       = "Allow all inbound from VPC"

  cidr_ipv4   = aws_vpc.main.cidr_block
  ip_protocol = "-1"

  tags = {
    Name = "${var.project_name}-jumpbox-all-inbound-vpc"
  }
}

resource "aws_vpc_security_group_ingress_rule" "jumpbox_public_nic_inbound_admin" {
  security_group_id = aws_security_group.jumpbox_instance.id
  description       = "Allow all inbound from admin IP"

  cidr_ipv4   = var.admin_ip
  ip_protocol = "-1"

  tags = {
    Name = "${var.project_name}-jumpbox-all-inbound-admin"
  }
}

resource "aws_vpc_security_group_egress_rule" "jumpbox_public_nic_all_outbound" {
  security_group_id = aws_security_group.jumpbox_instance.id
  description       = "Allow all outbound"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "-1"

  tags = {
    Name = "${var.project_name}-jumpbox-all-outbound"
  }
}

###########################################################
# SSH login script to NAT instance
###########################################################

resource "local_file" "jumpbox_login" {
  content = <<-EOF
#!/bin/bash
ssh -i ${local.ssh_key_path}/id_ed25519 \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    ${local.ami_user}@${aws_instance.jumpbox_instance.public_ip}
EOF
  filename = "${local.script_path}/jumpbox-login.sh"
  file_permission = "0755"
}