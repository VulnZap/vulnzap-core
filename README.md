# VulnZap Core

VulnZap is a powerful security tool designed to protect your AI-generated code from vulnerabilities in real-time. It provides seamless integration with AI-powered IDEs and offers comprehensive vulnerability scanning for your project dependencies.

```
  ╦  ╦┬ ┬┬  ┌┐┌╔═╗┌─┐┌─┐
  ╚╗╔╝│ ││  │││╔═╝├─┤├─┘
   ╚╝ └─┘┴─┘┘└┘╚═╝┴ ┴┴  
```

## Features

- Real-time vulnerability scanning for AI-generated code
- Integration with AI-powered IDEs (currently supports Cursor)
- Batch scanning of project dependencies
- Support for multiple package ecosystems (npm, pip)
- Detailed vulnerability reports and advisories
- GitHub Security Advisory Database integration
- National Vulnerability Database (NVD) integration

## Prerequisites

Before using VulnZap, you need to set up the following environment variables:

- `VULNZAP_GITHUB_TOKEN`: Your GitHub token for accessing the Security Advisory Database
- `VULNZAP_NVD_API_KEY`: Your NVD API key for accessing the National Vulnerability Database

## Installation

```bash
npm install -g vulnzap-core
```

## Getting Started

1. Initialize VulnZap in your project:
```bash
vulnzap init
```

2. Connect VulnZap to your IDE (currently supports Cursor):
```bash
vulnzap connect --ide cursor
```

## Commands

### Initialize Project
```bash
vulnzap init
```
Initializes VulnZap in your project by creating necessary configuration files.

### Connect to IDE
```bash
vulnzap connect --ide <ide-name>
```
Connects VulnZap to your AI-powered IDE. Currently supports:
- cursor

### Check Single Package
```bash
vulnzap check <package> --ecosystem <ecosystem> [--version <version>]
```
Check a specific package for vulnerabilities.

Examples:
```bash
# Check npm package
vulnzap check npm:express@4.17.1
# Or
vulnzap check express --ecosystem npm --version 4.17.1

# Check pip package
vulnzap check pip:requests@2.26.0
# Or
vulnzap check requests --ecosystem pip --version 2.26.0
```

### Batch Scan
```bash
vulnzap batch [--output <file>]
```
Automatically scans all dependencies in your project by:
- Reading package.json for npm dependencies
- Reading requirements.txt for Python dependencies

The results will be saved to:
- Default: vulnzap-results.json
- Custom location if specified with --output

### Start Security Bridge
```bash
vulnzap secure [--port <port>]
```
Starts the VulnZap security bridge for real-time protection of AI-generated code.

Options:
- `--port`: Specify custom port (default: 3456)
- `--ide`: Specify IDE integration
- `--mcp`: Use Model Context Protocol

## Configuration

VulnZap stores its configuration and scan history in the `.vulnzap-core` directory of your project:
- `scans.json`: Contains history of all vulnerability scans

## Integration with IDEs

### Cursor Integration
1. Install Cursor IDE
2. Run `vulnzap connect --ide cursor`
3. Start VulnZap security bridge with `vulnzap secure`

## Vulnerability Reports

Vulnerability scan results include:
- Package details (name, version, ecosystem)
- Found vulnerabilities and their severity
- CVE IDs when available
- Detailed descriptions of vulnerabilities
- Suggested fixed versions
- Advisory information from GitHub and NVD

## Best Practices

1. Always initialize VulnZap in your project before running scans
2. Regularly run batch scans to check all dependencies
3. Set up IDE integration for real-time protection
4. Keep your environment variables (VULNZAP_GITHUB_TOKEN, VULNZAP_NVD_API_KEY) secure
5. Review and update dependencies when vulnerabilities are found

## Limitations

- Currently in OSS version with some features unavailable
- IDE integration limited to Cursor
- Requires GitHub token and NVD API key for full functionality

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License
MIT License

Copyright (c) 2025 VulnZap

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. 