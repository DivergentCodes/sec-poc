# NPM Script Hook Detection

Analyze NPM packages to detect lifecycle script hooks in their dependencies. This tool helps identify potentially risky NPM packages by scanning for pre/post-install scripts and other lifecycle hooks that could execute arbitrary code.

For more information on lifecycle scripts, see the [NPM docs](https://docs.npmjs.com/cli/v11/using-npm/scripts).

## Features

- Analyzes dependencies from a local `package.json` file or a specified NPM package
- Detects the following lifecycle script hooks:
  - `preinstall`, `install`, `postinstall`
  - `preuninstall`, `uninstall`, `postuninstall`
  - `prepack`, `postpack`
- Concurrent processing of dependencies for faster analysis
- JSON output for easy integration with other tools

## Installation

### Build From Source

```bash
make build
```

### Install From Source

```bash
go install github.com/your-username/ls-npm-hooks@latest
```

### Install the Binary

```bash
curl -L https://github.com/your-username/ls-npm-hooks/releases/download/v0.1.0/ls-npm-hooks_linux_amd64.tar.gz | tar xz
```


## Usage

### Analyze Local package.json

```bash
# Analyze package.json in the current directory
npm-script-hook-detection

# Analyze a specific package.json file
npm-script-hook-detection -package /path/to/package.json
```


### Analyze NPM Package

```bash
# Analyze dependencies of a specific npm package
npm-script-hook-detection -npm express
```


## Output

The program outputs JSON-formatted results containing packages that have lifecycle scripts:

```json
[
  {
    "name": "package-name",
    "version": "1.0.0",
    "scripts": {
      "postinstall": "node scripts/postinstall.js",
      "preuninstall": "node scripts/preuninstall.js"
    }
  }
]
```


## Why This Matters

Lifecycle scripts in npm packages can pose security risks as they execute automatically during package installation or removal. This tool helps identify such scripts in your dependency tree, allowing you to:

- Audit dependencies for potentially malicious code
- Make informed decisions about package inclusion
- Enhance your project's security posture

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[Add your chosen license here]
