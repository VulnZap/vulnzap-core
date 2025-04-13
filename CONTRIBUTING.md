# Contributing to VulnZap-core

First off, thank you for considering contributing to VulnZap! It's people like you that make VulnZap such a great tool.

## Code of Conduct

By participating in this project, you agree to abide by the VulnZap [Code of Conduct](CODE_OF_CONDUCT.md). Please read it to understand the expectations for our community.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for VulnZap. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

Before creating bug reports, please check [the issue list](https://github.com/vulnzap/vulnzap/issues) as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible.

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for VulnZap, including completely new features and minor improvements to existing functionality.

Before creating enhancement suggestions, please check [the issue list](https://github.com/vulnzap/vulnzap/issues) as you might find out that you don't need to create one. When you are creating an enhancement suggestion, please include as many details as possible.

### Pull Requests

The process described here has several goals:

- Maintain VulnZap's quality
- Fix problems that are important to users
- Engage the community in working toward the best possible VulnZap
- Enable a sustainable system for VulnZap's maintainers to review contributions

Please follow these steps to have your contribution considered by the maintainers:

1. Fork the repository
2. Create a new branch for your feature or bugfix (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting to ensure your changes meet quality standards
5. Commit your changes (`git commit -m 'Add some amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

While the prerequisites above must be satisfied prior to having your pull request reviewed, the reviewer(s) may ask you to complete additional design work, tests, or other changes before your pull request can be ultimately accepted.

## Styleguides

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line
* Consider starting the commit message with an applicable emoji:
    * 🐛 `:bug:` when fixing a bug
    * ✨ `:sparkles:` when adding a new feature
    * 📚 `:books:` when adding or updating documentation
    * 🧹 `:broom:` when refactoring code
    * 🧪 `:test_tube:` when adding tests
    * 🔧 `:wrench:` when updating configuration files

### JavaScript/TypeScript Styleguide

All JavaScript/TypeScript code is linted with ESLint. To check your code formatting, run:

```bash
npm run lint
```

To automatically fix most linting issues, run:

```bash
npm run lint:fix
```

### Testing

Please include tests for any new functionality or bugfix. We use Jest for testing. To run tests:

```bash
npm test
```

## Development Setup

To set up VulnZap for local development:

1. Clone the repository:
```bash
git clone https://github.com/vulnzap/vulnzap.git
```

2. Install dependencies:
```bash
cd vulnzap
npm install
```

3. Create a `.env` file with required configuration:
```bash
cp .env.example .env
# Edit .env with your configuration values
```

4. Set up the database:
```bash
npm run db:seed
```

5. Run in development mode:
```bash
npm run dev
```

## Financial Contributions

We accept financial contributions through [Open Collective](https://opencollective.com/vulnzap). These contributions will help us improve VulnZap and support the open-source community.

## Questions?

If you have any questions, please feel free to join our [Discord](https://discord.gg/vulnzap) server or open an issue on GitHub. 