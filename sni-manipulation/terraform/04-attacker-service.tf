###############################################################################
# Attacker service instance.
###############################################################################

# VM for attacker service instance.
resource "aws_instance" "attacker_service" {
  instance_type = var.instance_type
  ami           = data.aws_ami.al2023.id
  key_name      = aws_key_pair.deployer_ed25519.key_name
  subnet_id     = aws_subnet.public.id

  user_data_replace_on_change = true

  vpc_security_group_ids = [aws_security_group.attacker_service.id]

  metadata_options {
    # Whether the IMDS is enabled.
    http_endpoint = "enabled"
    # Force IMDSv2 to prevent SSRF.
    http_tokens   = "required"
  }

  tags = {
    Name = "${var.project_name}-attacker-instance-subnet-az${var.availability_zone}"
  }

  depends_on = [ aws_security_group.attacker_service ]
}

###############################################################################
# Security group for attacker instance.
###############################################################################

resource "aws_security_group" "attacker_service" {
  vpc_id = aws_vpc.main.id

  name        = "${var.project_name}-attacker-instance-az${var.availability_zone}-${random_id.instance.id}"
  description = "Attacker network interface on the private network subnet."

  tags = {
    Name = "${var.project_name}-attacker-instance-az${var.availability_zone}-${random_id.instance.id}"
  }
}

resource "aws_vpc_security_group_ingress_rule" "attacker_public_inbound_https" {
  description       = "Allow HTTPS inbound from anywhere"
  security_group_id = aws_security_group.attacker_service.id

  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.project_name}-attacker-inbound-vpc"
  }
}

resource "aws_vpc_security_group_ingress_rule" "attacker_private_nic_inbound_admin" {
  security_group_id = aws_security_group.attacker_service.id
  description       = "Allow all inbound from admin IP"

  cidr_ipv4   = var.admin_ip
  ip_protocol = "-1"

  tags = {
    Name = "${var.project_name}-attacker-inbound-admin"
  }
}

resource "aws_vpc_security_group_egress_rule" "attacker_private_nic_all_outbound" {
  security_group_id = aws_security_group.attacker_service.id
  description       = "Allow all outbound"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "-1"

  tags = {
    Name = "${var.project_name}-attacker-all-outbound"
  }
}

###########################################################
# SSH login script to attacker instance
###########################################################

resource "local_file" "ssh_attacker_instance" {
  content = <<-EOF
#!/bin/bash
ssh -i ${local.ssh_key_path}/id_ed25519 \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    ec2-user@${aws_instance.attacker_service.public_ip}
EOF
  filename = "${path.module}/scripts/ssh_attacker_instance.sh"
  file_permission = "0755"
}
