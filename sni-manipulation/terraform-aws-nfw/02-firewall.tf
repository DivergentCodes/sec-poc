###########################################################
# Network Firewall Rule Group
###########################################################

resource "aws_networkfirewall_rule_group" "domain_filtering" {
  name     = "${var.project_name}-domain-filtering"
  type     = "STATEFUL"
  capacity = 100

  rule_group {
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }

    rules_source {
      rules_source_list {
        generated_rules_type = "ALLOWLIST"
        target_types        = ["HTTP_HOST", "TLS_SNI"]
        targets             = var.allowed_egress_web_domains
      }
    }
  }

  tags = {
    Name = "${var.project_name}-domain-filtering"
  }
}

###########################################################
# Network Firewall Policy
###########################################################

resource "aws_networkfirewall_firewall_policy" "main" {
  name = "${var.project_name}-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    stateful_default_actions           = ["aws:drop_established"]

    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.domain_filtering.arn
      priority     = 100
    }

    stateful_engine_options {
      rule_order              = "STRICT_ORDER"
      stream_exception_policy = "DROP"
    }
  }

  tags = {
    Name = "${var.project_name}-policy"
  }
}

###########################################################
# Network Firewall
###########################################################

resource "aws_networkfirewall_firewall" "main" {
  name                = "${var.project_name}-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = aws_vpc.main.id

  subnet_mapping {
    subnet_id = aws_subnet.public.id
    ip_address_type = "IPV4"
  }

  tags = {
    Name = "${var.project_name}-firewall"
  }
}

###########################################################
# Create the default route
###########################################################

resource "aws_route" "private_default" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = one(aws_networkfirewall_firewall.main.firewall_status[0].sync_states[*].attachment[0].endpoint_id)

  depends_on = [
    aws_route_table.private,
    aws_networkfirewall_firewall.main,
  ]
}
