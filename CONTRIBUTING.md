# Contributing to VulnZap

First off, thank you for considering contributing to VulnZap! It's people like you that make VulnZap such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* Use a clear and descriptive title
* Describe the exact steps which reproduce the problem
* Provide specific examples to demonstrate the steps
* Describe the behavior you observed after following the steps
* Explain which behavior you expected to see instead and why
* Include any error messages or logs

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* A clear and descriptive title
* A detailed description of the proposed functionality
* Explain why this enhancement would be useful
* List any similar features in other tools if applicable

### Pull Requests

* Fork the repo and create your branch from `main`
* If you've added code that should be tested, add tests
* Ensure the test suite passes
* Make sure your code lints
* Update the documentation

## Development Setup

1. Fork and clone the repo
```bash
git clone https://github.com/VulnZap/vulnzap-core.git
```

2. Install dependencies
```bash
npm install
```

3. Create a branch for your changes
```bash
git checkout -b feature/your-feature-name
```

4. Set up environment variables
```bash
VULNZAP_GITHUB_TOKEN=your_github_token
VULNZAP_NVD_API_KEY=your_nvd_api_key
```

## Style Guide

* Use TypeScript for all new code
* Follow the existing code style
* Use meaningful variable and function names
* Add comments for complex logic
* Keep functions small and focused
* Use async/await instead of callbacks

## Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

## Documentation

* Update the README.md with details of changes to the interface
* Update the API documentation for any modified endpoints
* Add examples for new features
* Document any new environment variables or dependencies

## Release Process

1. Update the version in package.json
2. Update CHANGELOG.md
3. Create a new release on GitHub
4. Publish to npm

## Questions?

Feel free to open an issue with your question or contact the maintainers directly.

Thank you for contributing to VulnZap! 🚀 