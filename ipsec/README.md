# IPSec Environments & Exploration

# Site-to-Site IPSec Tunnel with StrongSwan

This is a proof of concept for setting up a site-to-site IPSec tunnel between two StrongSwan containers using Docker Compose.

## Architecture

- Two StrongSwan containers (site-a and site-b)
- Network ranges:
  - Site A: 172.20.0.0/16 (172.20.0.2 for the StrongSwan container)
  - Site B: 172.21.0.0/16 (172.21.0.2 for the StrongSwan container)
  - VPN: 10.0.0.0/24 (configured in the tunnel but not used in this PoC)
- IKEv2 with AES-256 encryption and SHA-256 authentication
- Pre-shared key authentication


## Prerequisites

- Docker
- Docker Compose
- OpenSSL (for generating secrets)

## Setup

1. Generate the secrets:
   ```bash
   cd docker
   chmod +x generate-secrets.sh
   ./generate-secrets.sh
   ```
   This will:
   - Generate a random PSK
   - Create secret files for both sites
   - Create a .env file
   - Set proper file permissions
   - The generated files will be in the `secrets/` directory

2. Build and start the containers:
   ```bash
   docker-compose up --build
   ```

Note: The `secrets/` directory and its contents are git-ignored. Never commit the generated secrets to version control.
An example secrets file (`secrets.example`) is provided to show the format.

## Testing the Tunnel

1. Check the tunnel status on site-a:
   ```bash
   docker exec site-a-strongswan ipsec statusall
   ```

2. Check the tunnel status on site-b:
   ```bash
   docker exec site-b-strongswan ipsec statusall
   ```

3. Test connectivity between sites using the included test services:
   - A web service runs in site B (172.21.0.3:8080)
   - A client container in site A (172.20.0.3) automatically tests the connection every 30 seconds
   - The client container will curl both the main page and status page

4. View the test results:
   ```bash
   # View client logs (shows curl results)
   docker logs site-a-client

   # View web service logs
   docker logs site-b-web
   ```

5. Manual testing from site A client:
   ```bash
   # Get an interactive shell in the client container
   docker exec -it site-a-client sh

   # Test connectivity to the web service
   curl http://172.21.0.3:8080/
   curl http://172.21.0.3:8080/status
   ```

The test setup includes:
- Site A client (172.20.0.3): A curl container that periodically tests the connection
- Site B web service (172.21.0.3): An nginx container serving test pages
- Both services are on their respective site networks
- Traffic between them is encrypted through the IPSec tunnel

## Security Notes

- The pre-shared key in the configuration files should be changed to a strong, unique value
- The containers require NET_ADMIN capability for proper IPSec operation
- All traffic between the sites is encrypted using AES-256
- IKEv2 is used for key exchange with perfect forward secrecy

## Troubleshooting

- Check the logs in `/var/log/charon.log` inside each container
- Use `ipsec statusall` to see detailed tunnel information
- Ensure both containers can reach each other's IP addresses
- Verify that the pre-shared keys match on both sides
