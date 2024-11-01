# SNI Manipulation TypeScript Client

This is a TypeScript client for the SNI Manipulation PoC.
It sends a reverse shell to the server over a WebSocket connection.

## Requirements

Set up the server and make sure it's running.

```bash
make build
make run-server
```

## Usage

Run the client with the server IP, port, and SNI.

```bash
npm install
npm run client 127.0.0.1 8443 ubuntu.com
```
