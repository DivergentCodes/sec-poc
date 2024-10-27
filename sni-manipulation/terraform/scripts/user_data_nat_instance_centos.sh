#!/bin/bash

# Creates a NAT instance, with an optional transparent
# HTTP/HTTPS proxy that filters on domains.
#
# Tested on rpm/systemd based Linux.


INTERNAL_IFACE="enX0"


############################################################
# Squid Proxy
############################################################

function configure_squid_web_filtering {

    # Install packages.
    yum install -y squid

    # Domain Whitelist. Newline separated string of domains.
    echo -e '${allowed_egress_web_domains}' > /etc/squid/whitelist.txt

    # Initialize Squid's TLS certificate DB.
    mkdir /etc/squid/ssl
    pushd /etc/squid/ssl
    openssl genrsa -out squid.key 4096
    openssl req -new -key squid.key -out squid.csr -subj "/C=XX/ST=XX/L=squid/O=squid/CN=squid"
    openssl x509 -req -days 3650 -in squid.csr -signkey squid.key -out squid.crt
    cat squid.key squid.crt >> squid.pem
    popd
    sudo -u squid /usr/lib64/squid/security_file_certgen -c -s /var/spool/squid/ssl_db -M 4MB


    # Configure Squid.
    cat <<EOS > /etc/squid/squid.conf
visible_hostname squid
cache deny all

# Log format and rotation
logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %ssl::>sni %Sh/%<a %mt
logfile_rotate 10
debug_options rotate=10

# Handle HTTP requests
http_port 3128
http_port 3129 intercept

# Handle HTTPS requests
https_port 3130 cert=/etc/squid/ssl/squid.pem ssl-bump intercept
acl SSL_port port 443
http_access allow SSL_port
acl step1 at_step SslBump1
acl step2 at_step SslBump2
acl step3 at_step SslBump3
ssl_bump peek step1 all

# Deny requests to proxy instance metadata
acl instance_metadata dst 169.254.169.254
http_access deny instance_metadata

# Filter HTTP requests based on the whitelist
acl allowed_http_sites dstdomain "/etc/squid/whitelist.txt"
http_access allow allowed_http_sites

# Filter HTTPS requests based on the whitelist
acl allowed_https_sites ssl::server_name "/etc/squid/whitelist.txt"
ssl_bump peek step2 allowed_https_sites
ssl_bump splice step3 allowed_https_sites
ssl_bump terminate step2 all

http_access deny all
EOS

    # Start and enable the Squid service.
    systemctl start squid
    systemctl enable squid

    # Configure firewall transparent proxying rules.
    iptables -t nat -A PREROUTING -p tcp --dport 80  -j REDIRECT --to-port 3129
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 3130
}


############################################################
# Firewall and NAT
############################################################

function configure_nat {


    # Enable IP forwarding.
    sysctl -w net.ipv4.ip_forward=1

    # Configure firewall NAT rule.
    /sbin/iptables -t nat -A POSTROUTING -o "$INTERNAL_IFACE" -j MASQUERADE
}


############################################################
# Main
############################################################

# Install base packages.
yum install -y vim tmux iptables-services

configure_nat;

if [[ '${enable_egress_web_filtering}' ]]; then
    configure_squid_web_filtering;
fi

# Save firewall configuration.
service iptables save

# Plant a flag.
touch /home/ec2-user/bootstrapped
