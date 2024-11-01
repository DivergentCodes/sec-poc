# NPM Script Hooks

This directory contains a PoC that demonstrates how arbitrary commands
can run when NPM package dependencies are installed in a JavaScript project.

## Key Points

- NPM postinstall scripts run every time `npm install` is executed.
- Prevent failed hook scripts from causing `npm install` to fail by using `|| true`.
- Post-install local directory is `node_modules/<package-name>`.

## Setup

The Verdaccio registry is configured to run on port `4873` and has the predefined user `bob` with the password `hunter22`.

Local packages needs to be published to the Verdaccio registry before they can be installed to demonstrate the hook execution.

1. Start the Verdaccio registry with `npm run start:verdaccio`.
2. Publish the local packages to the Verdaccio registry with `npm publish`.
3. Run `npm install` in the `myapp` directory to trigger the postinstall scripts.

## Resources

- [NPM scripts](https://docs.npmjs.com/cli/v10/using-npm/scripts)
- [OWASP NPM Security best practices](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html#3-minimize-attack-surfaces-by-ignoring-run-scripts)