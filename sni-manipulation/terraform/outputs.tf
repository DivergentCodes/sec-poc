###########################################################
# Outputs
###########################################################

output "nat_instance_public_ip" {
  description = "The public IP of the NAT instance"
  value       = aws_instance.nat_instance.public_ip
}

output "ssh_private_key_path" {
  description = "Path to the SSH private key"
  value       = local_file.private_key.filename
}
