/**
 * Configuration for VulnZap
 * 
 * Environment variables should be set in a .env file or in the system environment
 */

import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// Load environment variables
dotenv.config();

// Get __dirname equivalent in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration object
export const config = {
  // App info
  app: {
    name: 'VulnZap Core',
    version: '1.0.0',
    homeDir: path.join(process.env.HOME || process.env.USERPROFILE || '', '.vulnzap-core'),
    tokenStorageKey: 'vulnzap-core_token',
    dataDir: path.join(__dirname, '../../data'),
  },

  // Server config
  server: {
    port: parseInt(process.env.PORT || '3456', 10),
    host: process.env.HOST || 'localhost',
  },

  // API endpoints
  api: {
    vulnerability: {
      github: '',
      nvd: '',
    },
  },
};

export default config; 