import WebSocket from 'ws';

async function connectWithSNI(ip: string, port: number, sni: string, message: string): Promise<void> {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(`wss://${ip}:${port}/ws`, {
            rejectUnauthorized: false,
            headers: {
                'Host': sni  // This sets the SNI
            }
        });

        ws.on('open', () => {
            console.log(`Connected to ${ip} with SNI: ${sni}`);
            ws.send(message);
            console.log(`Sent: ${message}`);
        });

        ws.on('message', (data) => {
            console.log(`Received: ${data.toString()}`);
        });

        ws.on('close', () => {
            console.log('Server ended connection');
            resolve();
        });

        ws.on('error', (err) => {
            reject(err);
        });
    });
}

async function main() {
    console.log("TypeScript client started");
    try {
        await connectWithSNI('127.0.0.1', 8443, 'example.com', 'Hello, Server!');
    } catch (error) {
        console.error('Connection failed:', error);
    }
}

main();