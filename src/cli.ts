#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora, { Ora } from 'ora';
import inquirer from 'inquirer';
import { startMcpServer, checkVulnerability } from './index.js';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import os from 'os';
import fs from 'fs';
import { spawn } from 'child_process';

// Get package version
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8'));
const version = packageJson.version;

const program = new Command(); // Instantiate Command

async function checkInit() {
  const vulnzapLocation = process.cwd() + '/.vulnzap-core';
  if (!fs.existsSync(vulnzapLocation)) {
    return false;
  }
  return true;
}

// Ensure .vulnzap folder exists in the user's home directory
const ensureVulnzapFolder = () => {
  const vulnzapHomeDir = join(os.homedir(), '.vulnzap');
  if (!fs.existsSync(vulnzapHomeDir)) {
    fs.mkdirSync(vulnzapHomeDir, { recursive: true });
  }
};
ensureVulnzapFolder();

// Banner display
const displayBanner = () => {
  console.log(chalk.bold(`
  ╦  ╦┬ ┬┬  ┌┐┌╔═╗┌─┐┌─┐
  ╚╗╔╝│ ││  │││╔═╝├─┤├─┘
   ╚╝ └─┘┴─┘┘└┘╚═╝┴ ┴┴  v${version}
  `));
  console.log(`${chalk.cyan('Securing AI-Generated Code')}\n`);
};

program
  .name('vulnzap-core')
  .description('Secure your AI-generated code from vulnerabilities in real-time')
  .version(version);
  
// Command: vulnzap secure (only used by ides to start a connection to the server)
program
  .command('secure')
  .description('Start the MCP security bridge to protect your AI coding')
  .option('--ide <ide-name>', 'Specify IDE integration (cursor, claude-code, windsurf)')
  .option('--port <port>', 'Port to use for MCP server', '3456')
  /**
   * Action handler for the 'secure' command.
   * Starts the MCP security bridge.
   * If VulnZap is not initialized in the current project, it will 
   * automatically perform the initialization steps before starting the server.
   */
  .action(async (options) => {
    try {
      // log the present working directory in log file at .cursor folder in home dir
      const homedir = os.homedir();
      const logFile = join(homedir, '.vulnzap', 'info.log');
      const logStream = fs.createWriteStream(logFile, { flags: 'a' });
      logStream.write(`VulnZap MCP server initialized by ${options.ide} started in ${process.cwd()} at ${new Date().toISOString()}\n`);
      logStream.end();

      const checkAlreadyInitialized = await checkInit();
      if (!checkAlreadyInitialized) {
        // Automatically initialize the project if not already done
        const vulnzapLocation = process.cwd() + '/.vulnzap-core';
        if (!fs.existsSync(vulnzapLocation)) {
          fs.mkdirSync(vulnzapLocation);
        }
        const scanConfigLocation = vulnzapLocation + '/scans.json';
        if (!fs.existsSync(scanConfigLocation)) {
          fs.writeFileSync(scanConfigLocation, JSON.stringify({
            scans: []
          }, null, 2));
        }
      }
      await startMcpServer({
        useMcp: options.mcp || true,
        ide: options.ide,
        port: parseInt(options.port, 10),
      });
    } catch (error: any) {
      console.error(chalk.red('Error:'), error.message); // Use console.error for errors
      process.exit(1);
    }
  });

// Command: vulnzap init
program
  .command('init')
  .description('Initialize VulnZap for your project')
  .action(async () => {
    displayBanner();

    console.log(chalk.yellow('You are on a OSS version. Some features may be unavailable.'));

    const spinner = ora('Initializing VulnZap...\n').start();

    const checkAlreadyInitialized = await checkInit();
    if (checkAlreadyInitialized) {
      console.log(chalk.green('✓') + ' VulnZap already initialized');
      process.exit(1);
    }

    try {
      const vulnzapLocation = process.cwd() + '/.vulnzap-core';
      if (!fs.existsSync(vulnzapLocation)) {
        fs.mkdirSync(vulnzapLocation);
      }
      const scanConfigLocation = vulnzapLocation + '/scans.json';
      if (!fs.existsSync(scanConfigLocation)) {
        fs.writeFileSync(scanConfigLocation, JSON.stringify({
          scans: []
        }, null, 2));
      }
      console.log(chalk.green('✓') + ' VulnZap config file created\n');
      spinner.succeed('wohooooo!');
      console.log(chalk.yellow('To enable GitHub integration, set the VULNZAP_GITHUB_TOKEN environment variable with your GitHub token'));
      console.log(chalk.yellow('To enable National Vulnerability Database(NVD) integration, set the VULNZAP_NVD_API_KEY environment variable with your NVD token'));
      console.log(chalk.green('✓') + ' VulnZap initialized successfully');
    } catch (error: any) {
      spinner.fail('Failed to initialize VulnZap');
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap check
program
  .command('check <package>')
  .description('Check a package for vulnerabilities (format: ecosystem:package-name@version)')
  .option('-e, --ecosystem <ecosystem>', 'Package ecosystem (npm, pip)')
  .option('-v, --version <version>', 'Package version')
  .action(async (packageInput, options) => {
    displayBanner();

    const checkAlreadyInitialized = await checkInit();
    if (!checkAlreadyInitialized) {
      console.error(chalk.red('Error: VulnZap is not initialized in this project, run vulnzap init to initialize VulnZap'));
      process.exit(1);
    }

    let packageName, packageVersion, packageEcosystem;

    if (!process.env.VULNZAP_GITHUB_TOKEN) {
      console.error(chalk.red('Error: VULNZAP_GITHUB_TOKEN not found'));
      process.exit(1);
    }
    if (!process.env.VULNZAP_NVD_API_KEY) {
      console.error(chalk.red('Error: VULNZAP_NVD_API_KEY token not found'));
      process.exit(1);
    }

    // Log the event
    const logFile = join(os.homedir(), '.vulnzap', 'info.log');
    const logStream = fs.createWriteStream(logFile, { flags: 'a' });
    logStream.write(`VulnZap check command executed for ${packageInput} at ${new Date().toISOString()}\n`);
    logStream.end();

    // Parse package input
    const packageFormat = /^(npm|pip):([^@]+)@(.+)$/;
    const match = packageInput.match(packageFormat);

    if (match) {
      [, packageEcosystem, packageName, packageVersion] = match;
    } else if (packageInput.includes('@') && !packageInput.startsWith('@')) {
      // Fallback for old format package@version
      [packageName, packageVersion] = packageInput.split('@');
      packageEcosystem = options.ecosystem;
    } else {
      packageName = packageInput;
      packageVersion = options.version;
      packageEcosystem = options.ecosystem;
    }

    if (!packageVersion) {
      console.error(chalk.red('Error: Package version is required'));
      console.log('Format: vulnzap check ecosystem:package-name@version');
      console.log('Example: vulnzap check npm:express@4.17.1');
      console.log('Or: vulnzap check package-name --ecosystem npm --version 4.17.1');
      process.exit(1);
    }

    if (!packageEcosystem) {
      console.error(chalk.red('Error: Package ecosystem is required'));
      console.log('Format: vulnzap check ecosystem:package-name@version');
      console.log('Example: vulnzap check npm:express@4.17.1');
      console.log('Or: vulnzap check package-name --ecosystem npm --version 4.17.1');
      process.exit(1);
    }

    const spinner = ora(`Checking ${packageEcosystem}:${packageName}@${packageVersion} for vulnerabilities...`).start();

    try {
      const result = await checkVulnerability(packageEcosystem, packageName, packageVersion);

      spinner.stop();

      console.log(chalk.green('✓') + ' Vulnerability scan completed');

      if (result.length === 0) {
        console.log(chalk.green(`✓ Safe: ${packageName}@${packageVersion} has no known vulnerabilities\n`));
        return;
      }

      for (const vuln of result) {
        if (vuln.isVulnerable) {
          console.log(chalk.red(`✗ Vulnerable: ${packageName}@${packageVersion} has vulnerabilities\n`));

          // Display vulnerability details
          vuln.advisories?.forEach(advisory => {
            console.log(chalk.yellow(`- ${advisory.title}`));
            console.log(`  Severity: ${advisory.severity}`);
            console.log(`  CVE: ${advisory.cve_id || 'N/A'}`);
            console.log(`  Description: ${advisory.description}`);
            console.log('');
          });

          // Suggest fixed version if available
          if (vuln.fixedVersions && vuln.fixedVersions.length > 0) {
            console.log(chalk.green('Suggested fix:'));
            console.log(`Upgrade to ${vuln.fixedVersions[0]} or later\n`);
          }
        } else {
          console.log(chalk.green(`✓ Safe: ${packageName}@${packageVersion} has no known vulnerabilities\n`));
        }
      }
      const pwd = process.cwd();
      const scanConfigLocation = pwd + '/.vulnzap-core/scans.json';
      const scanConfig = JSON.parse(fs.readFileSync(scanConfigLocation, 'utf8'));
      const newScan = {
        package: `${packageName}@${packageVersion}`,
        result: result,
        createdAt: new Date().toISOString()
      };
      scanConfig.scans.push(newScan);
      fs.writeFileSync(scanConfigLocation, JSON.stringify(scanConfig, null, 2));

      console.log(chalk.green('✓') + ' Vulnerability scan saved to ' + scanConfigLocation);
      process.exit(0);
    } catch (error: any) {
      spinner.fail('Vulnerability check failed');
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap connect
program
  .command('connect')
  .description('Connect VulnZap to your AI-powered IDE')
  .option('--ide <ide-name>', 'IDE to connect with (cursor, claude-code, windsurf)')
  .action(async (options) => {
    // Prompt for IDE if not provided

    if (!options.ide) {
      console.error(chalk.red('Error: You must specify an IDE to connect with.'));
      console.log('Example: vulnzap connect --ide <ide-name>');
      process.exit(1);
    }

    // Log the event
    const logFile = join(os.homedir(), '.vulnzap', 'info.log');
    const logStream = fs.createWriteStream(logFile, { flags: 'a' });
    logStream.write(`VulnZap connect command executed for ${options.ide} at ${new Date().toISOString()}\n`);
    logStream.end();
    

    if (options.ide === 'cursor') {
      const cursorMcpConfigLocation = os.homedir() + '/.cursor/mcp.json';
      if (!fs.existsSync(cursorMcpConfigLocation)) {
        console.error(chalk.red('Error: Cursor MCP config not found.'));
        console.log('Please install Cursor and try again.');
        process.exit(1);
      }
      const cursorMcpConfig = JSON.parse(fs.readFileSync(cursorMcpConfigLocation, 'utf8'));

      // Display info about API keys and ask if user has both
      console.log(chalk.cyan('To use the connect command, you need both a GitHub token and an NVD API key.'));
      console.log(chalk.yellow('GitHub token: https://github.com/settings/tokens'));
      console.log(chalk.yellow('NVD API key: https://nvd.nist.gov/developers/request-an-api-key'));
      console.log('\nBoth keys are required for full functionality.');
      const { hasKeys } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'hasKeys',
          message: 'Do you have both the GitHub token and NVD API key?',
          default: false,
        },
      ]);
      if (!hasKeys) {
        console.log(chalk.red('Please obtain both API keys before proceeding.'));
        process.exit(1);
      }

      // Prompt for GitHub and NVD API keys
      const answers = await inquirer.prompt([
        {
          type: 'input',
          name: 'githubToken',
          message: 'Enter your GitHub token:',
        },
        {
          type: 'input',
          name: 'nvdApiKey',
          message: 'Enter your NVD API key:',
        },
      ]);

      let missing = false;
      if (!answers.githubToken) {
        console.log(chalk.yellow('You can generate a GitHub token at: https://github.com/settings/tokens'));
        missing = true;
      }
      if (!answers.nvdApiKey) {
        console.log(chalk.yellow('You can request an NVD API key at: https://nvd.nist.gov/developers/request-an-api-key'));
        missing = true;
      }
      if (missing) {
        console.error(chalk.red('Error: Both API keys are required to proceed.'));
        process.exit(1);
      }

      // Save tokens in mcp.json
      if (!cursorMcpConfig.mcp) {
        cursorMcpConfig.mcpServers = {
          VulnZap: {
            command: "vulnzap",
            args: ["secure", "--ide", "cursor", "--port", "3456"],
            env: {
              VULNZAP_GITHUB_TOKEN: answers.githubToken,
              VULNZAP_NVD_API_KEY: answers.nvdApiKey
            }
          }
        };
      } else {
        cursorMcpConfig.mcpServers.VulnZap = {
          command: "vulnzap",
          args: ["secure", "--ide", "cursor", "--port", "3456"],
          env: {
            VULNZAP_GITHUB_TOKEN: answers.githubToken,
            VULNZAP_NVD_API_KEY: answers.nvdApiKey
          }
        };
      }
      fs.writeFileSync(cursorMcpConfigLocation, JSON.stringify(cursorMcpConfig, null, 2));
      console.log(chalk.green('✓') + ' Cursor MCP config updated successfully with API keys');
      process.exit(0);
    } else {
      console.error(chalk.red('Error: Unsupported IDE.'));
      console.log('Please use Cursor for now.');
      process.exit(1);
    }
  });

interface ScanResult {
  ecosystem: 'npm' | 'pip';
  package: string;
  version: string;
  result: any[];
}

// Command: vulnzap batch
program
  .command('batch')
  .description('Batch scan dependencies from package.json and requirements.txt')
  .option('-o, --output <file>', 'Output file for results (default: vulnzap-results.json)')
  .action(async (options) => {
    displayBanner();

    const checkAlreadyInitialized = await checkInit();
    if (!checkAlreadyInitialized) {
      console.error(chalk.red('Error: VulnZap is not initialized in this project, run vulnzap init to initialize VulnZap'));
      process.exit(1);
    }

    // Log the event
    const logFile = join(os.homedir(), '.vulnzap', 'info.log');
    const logStream = fs.createWriteStream(logFile, { flags: 'a' });
    logStream.write(`VulnZap batch scan command executed in ${process.cwd()} with output file ${options.output} at ${new Date().toISOString()}\n`);
    logStream.end();
    

    const spinner = ora('Initiating batch vulnerability scan...').start();
    const results: ScanResult[] = [];
    let totalPackages = 0;
    let vulnerablePackages = 0;
    let totalVulnerabilities = 0;

    try {
      // Check for package.json
      const packageJsonPath = join(process.cwd(), 'package.json');
      if (fs.existsSync(packageJsonPath)) {
        spinner.text = 'Scanning npm dependencies...';
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        const dependencies = {
          ...packageJson.dependencies || {},
          ...packageJson.devDependencies || {}
        };

        for (const [name, version] of Object.entries(dependencies)) {
          const cleanVersion = (version as string).replace(/[\^~]/g, '');
          spinner.text = `Scanning ${name}@${cleanVersion}...`;

          try {
            const vulnResult = await checkVulnerability('npm', name, cleanVersion);
            totalPackages++;

            if (vulnResult.length > 0 && vulnResult.some(r => r.isVulnerable)) {
              vulnerablePackages++;
              totalVulnerabilities += vulnResult.reduce((acc, r) =>
                acc + (r.advisories?.length || 0), 0);
            }

            results.push({
              ecosystem: 'npm',
              package: name,
              version: cleanVersion,
              result: vulnResult
            });
          } catch (error) {
            console.error(chalk.yellow(`Warning: Failed to scan ${name}@${cleanVersion}`));
          }
        }
      }

      // Check for requirements.txt
      const requirementsPath = join(process.cwd(), 'requirements.txt');
      if (fs.existsSync(requirementsPath)) {
        spinner.text = 'Scanning Python dependencies...';
        const requirements = fs.readFileSync(requirementsPath, 'utf8')
          .split('\n')
          .filter(line => line && !line.startsWith('#'))
          .map(line => {
            const [name, version] = line.split('==');
            return { name: name.trim(), version: version ? version.trim() : 'latest' };
          });

        for (const pkg of requirements) {
          spinner.text = `Scanning ${pkg.name}@${pkg.version}...`;

          try {
            const vulnResult = await checkVulnerability('pip', pkg.name, pkg.version);
            totalPackages++;

            if (vulnResult.length > 0 && vulnResult.some(r => r.isVulnerable)) {
              vulnerablePackages++;
              totalVulnerabilities += vulnResult.reduce((acc, r) =>
                acc + (r.advisories?.length || 0), 0);
            }

            results.push({
              ecosystem: 'pip',
              package: pkg.name,
              version: pkg.version,
              result: vulnResult
            });
          } catch (error) {
            console.error(chalk.yellow(`Warning: Failed to scan ${pkg.name}@${pkg.version}`));
          }
        }
      }

      // Save results
      const outputFile = options.output || 'vulnzap-results.json';
      fs.writeFileSync(outputFile, JSON.stringify(results, null, 2));

      spinner.succeed('Batch scan completed');

      console.log('\nScan summary:');
      console.log(chalk.green('✓') + ` Packages scanned: ${totalPackages}`);
      console.log(chalk.red('✗') + ` Vulnerabilities found: ${totalVulnerabilities}`);
      console.log(chalk.yellow('!') + ` Packages with known issues: ${vulnerablePackages}`);
      console.log('\nDetailed results saved to:', outputFile);

      // Save to vulnzap scans history
      const scanConfigLocation = join(process.cwd(), '.vulnzap-core/scans.json');
      const scanConfig = JSON.parse(fs.readFileSync(scanConfigLocation, 'utf8'));
      scanConfig.scans.push({
        type: 'batch',
        results,
        summary: {
          totalPackages,
          vulnerablePackages,
          totalVulnerabilities
        },
        createdAt: new Date().toISOString()
      });
      fs.writeFileSync(scanConfigLocation, JSON.stringify(scanConfig, null, 2));
      process.exit(0);
    } catch (error: any) {
      spinner.fail('Batch scan failed');
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

// Command: vulnzap help
program
  .command('help')
  .description('Display help information')
  .action(() => {
    displayBanner();
    program.help();
  });

// Parse arguments
program.parse(process.argv);

// If no args, display help
if (process.argv.length === 2) {
  displayBanner();
  program.help();
} 