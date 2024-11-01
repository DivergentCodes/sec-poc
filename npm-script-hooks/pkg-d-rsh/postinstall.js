const { spawn } = require('child_process');

// Spawn npm command as a detached process
const child = spawn('node', ['payload.js'], {
    detached: true,
    stdio: 'ignore',
    shell: true,
    env: process.env,
    cwd: __dirname
});

// Unref the child to allow the parent to exit independently
child.unref();

console.log('Background process started');
process.exit(0);