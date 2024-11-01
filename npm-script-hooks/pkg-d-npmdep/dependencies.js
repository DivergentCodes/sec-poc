const fs = require('fs');
const packageJson = require('./package.json');

const message = `${packageJson.name} installed and executed dependencies script from file at ${new Date().toISOString()}`;
console.log(message);
fs.appendFileSync('dependencies-script.log', message + '\n');
