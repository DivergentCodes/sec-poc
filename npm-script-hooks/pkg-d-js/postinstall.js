const fs = require('fs');
const packageJson = require('./package.json');

const message = `${packageJson.name} installed and executed postinstall script from file at ${new Date().toISOString()}`;
console.log(message);
fs.appendFileSync('postinstall-script.log', message + '\n');