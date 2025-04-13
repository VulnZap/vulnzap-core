/**
 * Vulnzap Services Configuration
 * 
 * This file contains the core configuration for the Vulnzap SaaS platform.
 * It includes settings for all supported ecosystems, API endpoints, and service configurations.
 */

import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import os from 'os';

// Load environment variables
dotenv.config();

// ESM __dirname equivalent
const homeDir = os.homedir();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, '..', '..');

// Default configuration values
const DEFAULT_CONFIG = {
  // Server settings
  PORT: parseInt(process.env.PORT || '3000', 10),

  // Service endpoints
  SERVICE_ENDPOINTS: {
    GITHUB_ADVISORY: 'https://api.github.com/advisories',
    NVD_API: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    OSV_API: 'https://api.osv.dev/v1',
    OWASP_API: 'https://api.owasp.org/v1'
  },

  // API keys
  API_KEYS: {
    GITHUB: process.env.VULNZAP_GITHUB_TOKEN || '',
    NVD: process.env.VULNZAP_NVD_API_KEY || '',
    OWASP: process.env.VULNZAP_OWASP_API_KEY || ''
  },

  // Cache settings
  DATA_PATHS: {
    CACHE_DIR: process.env.CACHE_DIR || path.join(homeDir, '.vulnzap', 'cache'),
    DATA_DIR: path.join(PROJECT_ROOT, 'data'),
    REPORTS_DIR: process.env.REPORTS_DIR || './reports'
  },

  // Refresh intervals
  REFRESH_INTERVALS: {
    GITHUB: parseInt(process.env.GITHUB_REFRESH_INTERVAL || '86400000'), // 24 hours
    NVD: parseInt(process.env.NVD_REFRESH_INTERVAL || '86400000'), // 24 hours
  },

  // Rate limiting
  RATE_LIMITS: {
    MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '1000'), // 1000 requests per hour
    WINDOW_SIZE: parseInt(process.env.RATE_LIMIT_WINDOW_SIZE || '3600000'), // 1 hour
    NVD: {
      limit: 5,
      window: 30 * 1000
    }, // 5 requests per 30 seconds
  },

  // Supported ecosystems and their configurations
  ECOSYSTEMS: {
    npm: {
      name: 'npm',
      displayName: 'Node.js (npm)',
      versionParser: 'semver',
      packageManager: 'npm',
      installCommand: 'npm install {package}@{version}',
      updateCommand: 'npm update {package}',
      latestCommand: 'npm install {package}@latest',
      registryUrl: 'https://registry.npmjs.org/',
      searchUrl: 'https://registry.npmjs.org/-/v1/search?text={query}&size=20',
      packageUrl: 'https://www.npmjs.com/package/{package}',
      aliases: ['node', 'nodejs', 'javascript', 'js']
    },

    pip: {
      name: 'pip',
      displayName: 'Python (pip)',
      versionParser: 'pep440',
      packageManager: 'pip',
      installCommand: 'pip install {package}=={version}',
      updateCommand: 'pip install --upgrade {package}',
      latestCommand: 'pip install --upgrade {package}',
      registryUrl: 'https://pypi.org/pypi/',
      searchUrl: 'https://pypi.org/search/?q={query}',
      packageUrl: 'https://pypi.org/project/{package}/',
      aliases: ['python', 'pypi']
    },
  },

  // Default enabled ecosystems (can be overridden by env vars)
  ENABLED_ECOSYSTEMS: (process.env.ENABLED_ECOSYSTEMS || 'npm,pip').split(',')
    .map(eco => eco.trim())
    .filter(Boolean),

  // Ecosystem aliases map (initialized as empty)
  ECOSYSTEM_ALIASES: new Map<string, string>(),

  // Ecosystem map (initialized as empty)
  ECOSYSTEM_MAP: new Map<string, any>(),

  SUPPORTED_ECOSYSTEMS: [] as any[],
};

/**
 * Build the final configuration, merging environment variables and defaults
 */
function buildConfig() {
  const config = { ...DEFAULT_CONFIG };

  // Filter to only enabled ecosystems
  config.SUPPORTED_ECOSYSTEMS = config.ENABLED_ECOSYSTEMS
    .filter(eco => config.ECOSYSTEMS[eco])
    .map(eco => config.ECOSYSTEMS[eco]);

  // Convert to a map for faster lookups
  config.ECOSYSTEM_MAP = new Map(
    config.SUPPORTED_ECOSYSTEMS.map(eco => [eco.name, eco])
  );

  // Add ecosystem aliases for faster lookups
  config.ECOSYSTEM_ALIASES = new Map();
  config.SUPPORTED_ECOSYSTEMS.forEach(eco => {
    eco.aliases.forEach(alias => {
      config.ECOSYSTEM_ALIASES.set(alias, eco.name);
    });
    // Add the main name as an alias to itself for consistency
    config.ECOSYSTEM_ALIASES.set(eco.name, eco.name);
  });

  return config;
}

// Export the final configuration
const CONFIG = buildConfig();
export default CONFIG; 