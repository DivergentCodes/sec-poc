#!/bin/bash

# Creates an attacker server environment.
#
# Tested on rpm/systemd based Linux.

############################################################
# Main
############################################################

# Install base packages.
yum install -y \
    vim \
    tmux \
    iptables-services \
    nginx \
    ;

configure_nat;

configure_squid_web_filtering;

# Save firewall configuration.
service iptables save

# Plant a flag.
touch /home/ec2-user/bootstrapped
