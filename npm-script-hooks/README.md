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

1. Start the Verdaccio registry with `make start-registry`.
2. Publish the local packages to the Verdaccio registry with `make publish`.
3. Trigger the postinstall scripts by running `npm install` in the `myapp` directory.
4. Look at the logs in the Verdaccio registry `myapp/node_modules/<package-name>/postinstall-scripts.log` files to see the hook execution.

The reverse shell payload can be caught by running the SNI server PoC in a separate terminal with `./server 127.0.0.1 8443`.

## Resources

- [NPM scripts](https://docs.npmjs.com/cli/v10/using-npm/scripts)
- [OWASP NPM Security best practices](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html#3-minimize-attack-surfaces-by-ignoring-run-scripts)