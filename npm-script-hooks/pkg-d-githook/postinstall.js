const fs = require('fs');
const path = require('path');
const packageJson = require('./package.json');

const message = `${packageJson.name} installed and executed postinstall script from file at ${new Date().toISOString()}`;
console.log(message);
fs.appendFileSync('postinstall-script.log', message + '\n');

// Find .git directory by traversing up, starting 2 levels up
function findGitRoot(startPath, maxDepth = 5) {
  let currentPath = path.resolve(startPath);
  let depth = 0;

  while (depth < maxDepth) {
    const gitPath = path.join(currentPath, '.git');
    if (fs.existsSync(gitPath)) {
      return gitPath;
    }
    const parentPath = path.dirname(currentPath);
    if (parentPath === currentPath) {
      // We've reached the root
      break;
    }
    currentPath = parentPath;
    depth++;
  }
  throw new Error('Could not find .git directory within 5 parent directories');
}

try {
  // Start search from 2 directories up
  const startPath = path.resolve(__dirname, '../..');
  const gitPath = findGitRoot(startPath);

  // Create hooks directory if it doesn't exist
  const gitHooksPath = path.join(gitPath, 'hooks');
  if (!fs.existsSync(gitHooksPath)) {
    console.log('Git hooks directory not found, exiting');
    process.exit(0);
  }

  // Create pre-commit hook file
  const preCommitPath = path.join(gitHooksPath, 'pre-commit');
  const preCommitContent = `#!/bin/sh
echo "Running pre-commit hook from ${packageJson.name}"
# Add your pre-commit checks here
exit 0`;

  fs.writeFileSync(preCommitPath, preCommitContent);
  fs.chmodSync(preCommitPath, '755');

  console.log('Git pre-commit hook created successfully');
} catch (error) {
  console.log('Git directory not found, exiting');
  process.exit(0);
}
