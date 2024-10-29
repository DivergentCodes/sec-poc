###########################################################
# Outputs
###########################################################

output "ssh_private_key_path" {
  description = "Path to the SSH private key"
  value       = local_file.private_key.filename
}

output "jumpbox_instance_public_ip" {
  description = "The public IP of the jumpbox instance"
  value       = aws_instance.jumpbox_instance.public_ip
}

output "internal_instance_private_ip" {
  description = "The private IP of the internal instance"
  value       = aws_instance.internal_instance.private_ip
}

output "attacker_instance_public_ip" {
  description = "The public IP of the attacker service instance"
  value       = aws_instance.attacker_service.public_ip
}