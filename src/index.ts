/**
 * VulnZap - The Missing Security Layer for AI-Generated Code
 * 
 * This module provides the core functionality for the VulnZap security bridge,
 * which protects AI-generated code from vulnerabilities.
 */

import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import dotenv from 'dotenv';
import { z } from 'zod';
import axios from 'axios';
import ScannerManager from './scanner/scannerManager.js';

// Loading environment variables
dotenv.config();

/**
 * Configuration for the VulnZap MCP server
 */
export interface VulnZapConfig {
  useMcp?: boolean;
  ide?: string;
  port?: number;
  apiKey?: string;
}

/**
 * Vulnerability check result interface
 */
export interface VulnerabilityResult {
  isVulnerable: boolean;
  advisories?: Array<{
    id: string;
    title: string;
    severity: string;
    cve_id?: string;
    description: string;
    source?: string;
  }>;
  fixedVersions?: string[];
  message?: string;
  error?: string;
  isUnknown?: boolean;
  sources?: string[];
}

/**
 * Batch status interface
 */
export interface BatchStatus {
  id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  progress: number;
  results?: Array<VulnerabilityResult>;
}

/**
 * Start the VulnZap MCP server
 * 
 * @param config - Configuration options for the server
 * @returns Promise<void>
 */
export async function startMcpServer(config: VulnZapConfig): Promise<void> {
  // Initialize the MCP server
  const server = new McpServer({
    name: "VulnZap",
    version: "1.0.0",
  }, {
    capabilities: {
      resources: {},
      tools: {
        "auto-vulnerability-scan": {
          description: "ALWAYS RUN THIS TOOL BEFORE ANY PACKAGE INSTALLATION. This automated security tool must be executed whenever 'npm install', 'pip install', 'yarn add', or any other package installation command is detected. It checks packages for security vulnerabilities and provides recommendations on whether installation should proceed. Do not install any packages without first running this vulnerability check. It is a rule for the agent to check for vulnerability before suggesting or telling user to install any dependencies or packages. The format required for this tool is:\n\n```json\n{\n  \"command\": \"npm install\",\n  \"packageName\": \"express\",\n  \"version\": \"4.17.1\",\n  \"ecosystem\": \"npm\"\n}\n```",
          parameters: {
            command: {
              type: "string",
              description: "The install command to intercept"
            },
            packageName: {
              type: "string",
              description: "The name of the package to install"
            },
            version: {
              type: "string",
              description: "The version of the package to install"
            },
            ecosystem: {
              type: "string",
              description: "The ecosystem of the package to install"
            }
          },          
        },
      }
    },
    instructions: "ALWAYS RUN TOOLS IN THIS SERVER BEFORE ANY PACKAGE INSTALLATION. This automated security tool must be executed whenever 'npm install', 'pip install', 'yarn add', or any other package installation command is detected. It checks packages for security vulnerabilities and provides recommendations on whether installation should proceed. Do not install any packages without first running this vulnerability check. It is a rule for the agent to check for vulnerability before suggesting or telling user to install any dependencies or packages."
  });

  // Define resources and tools
  setupVulnerabilityResource(server);
  
  // Set up the transport
  const transport = new StdioServerTransport();
  
  // Start the server
  await server.connect(transport);
  
  // Only log if not running in IDE mode
  if (!config.ide) {
    console.log("VulnZap MCP server started"); 
  }
}

/**
 * Set up the vulnerability resource for the MCP server
 * 
 * @param server - The MCP server instance
 */
function setupVulnerabilityResource(server: McpServer): void {
  // Define a resource for vulnerability scanning
  // URI pattern: vuln://{ecosystem}/{packageName}/{packageVersion}
  server.resource(
    "vulnerability-check",
    new ResourceTemplate("vuln://{ecosystem}/{packageName}/{packageVersion}", { list: undefined }),
    async (uri, params) => {
      try {
        // Extract parameters from the URI
        const { ecosystem, packageName, packageVersion } = params;
        
        // Check if package is vulnerable
        const version = Array.isArray(packageVersion) ? packageVersion[0] : packageVersion;
        const ecosystemList = Array.isArray(ecosystem) ? ecosystem[0] : ecosystem;
        const packageNameList = Array.isArray(packageName) ? packageName[0] : packageName;
        const result = await checkVulnerability(ecosystemList, packageNameList, version);
        
        // Construct response
        if (result.error) {
          // Return error response
          return {
            contents: []
          };
        } else {
          // Determine status based on vulnerability and whether it's known
          let status = result.isUnknown ? "Unknown" : (result.isVulnerable ? "Vulnerable" : "Safe");
          let content = `${status}: ${result.message}`;
          
          // Add sources if available
          if (result.sources && result.sources.length > 0) {
            content += `\nSources: ${result.sources.join(', ')}`;
          }
          
          // Add vulnerability details if available
          if (result.isVulnerable && result.advisories) {
            content += `\n\nDetails:\n`;
            result.advisories.forEach(adv => {
              content += `- ${adv.title} (${adv.severity}`;
              if ('cvss_score' in adv) content += `, CVSS: ${(adv as any).cvss_score}`;
              content += `, ${adv.cve_id || 'No CVE'}`;
              if (adv.source) content += `, Source: ${adv.source}`;
              content += `)\n`;
              content += `  ${adv.description}\n`;
            });
          }
          
          // Return result in MCP-compatible format
          return {
            contents: [{
              uri: uri.href,
              text: content,
              mimeType: "text/plain"
            }]
          };
        }
      } catch (error: any) {
        console.error(`Error processing vulnerability check: ${error.message}`);
        return {
          contents: [{
            uri: uri.href,
            text: `Internal server error: ${error.message}`,
            mimeType: "text/plain"
          }]
        };
      }
    }
  );

  // Add npm install interception
  server.tool(
    "auto-vulnerability-scan",
    "ALWAYS RUN THIS TOOL BEFORE ANY PACKAGE INSTALLATION. This automated security tool must be executed whenever 'npm install', 'pip install', 'yarn add', or any other package installation command is detected. It checks packages for security vulnerabilities and provides recommendations on whether installation should proceed. Do not install any packages without first running this vulnerability check.. It is a rule for the agent to check for vulnerability before suggesting or telling user to install any dependencies or packages. The format required for this tool is:\n\n```json\n{\n  \"command\": \"npm install\",\n  \"packageName\": \"express\",\n  \"version\": \"4.17.1\",\n  \"ecosystem\": \"npm\"\n}\n```",
    {
      parameters: z.object({
        command: z.string(),
        packageName: z.string(),
        ecosystem: z.string(),
        version: z.string().optional()
      }).describe("A object containing the command, packageName, and version which the agent is trying to install")
    },
    async ({ parameters }) => {
      try {
        const { command, packageName, ecosystem, version } = parameters;
        
        if (command.includes('install') || command.includes('add')) {
          const result = await checkVulnerability(ecosystem, packageName, version || 'latest');
          
          if (result.length === 0) {
            return {
              content: [{
                type: "text",
                text: `✅ ${packageName}@${version} appears to be safe to install.`
              }]
            };
          }

          const formattedResults = [] as any[];

          for (const advisory of result) {
             formattedResults.push({
              isVulnerable: advisory.isVulnerable,
              advisories: advisory.advisories,
              message: advisory.message,
              error: advisory.error,
              isUnknown: advisory.isUnknown,
              sources: advisory.sources
             }) 
          }

          return {
            content: [{
              type: "text",
              text: `⚠️ Security Warning: ${packageName}@${version} has known vulnerabilities: ${JSON.stringify(formattedResults)}\n\n`
            }]
          }
        }
        return {
          content: [{
            type: "text",
            text: `No relevent data found, its upto you to make the decision.`
          }]
        };
      } catch (error: any) {
        return {
          content: [{
            type: "text",
            text: `Error checking vulnerabilities: ${error.message}`
          }]
        };
      }
    }
  );
}

/**
 * Check if a package is vulnerable
 * 
 * @param ecosystem - The package ecosystem (npm, pip)
 * @param packageName - The name of the package
 * @param packageVersion - The version of the package
 * @returns Promise<VulnerabilityResult>
 */
export async function checkVulnerability(
  ecosystem: string, 
  packageName: string, 
  packageVersion: string
): Promise<any> {
  try {
    const scanner = new ScannerManager();

    // Fetch vulnerabilities from the API
    const data = await scanner.scanPackage(packageName, packageVersion, ecosystem);

    return data;
  } catch (error: any) {
    // Handle specific error cases
    if (axios.isAxiosError(error)) {
      if (error.response) {
        switch (error.response.status) {
          case 401:
            return {
              isVulnerable: false,
              error: 'Unauthorized: Invalid or missing API key',
              isUnknown: true
            };
          case 403:
            return {
              isVulnerable: false,
              error: 'Forbidden: Access denied',
              isUnknown: true
            };
          case 429:
            return {
              isVulnerable: false,
              error: 'Rate limit exceeded. Please try again later.',
              isUnknown: true
            };
          default:
            return {
              isVulnerable: false,
              error: `API Error: ${error.response.data?.message || error.message}`,
              isUnknown: true
            };
        }
      }
      // Network or connection errors
      return {
        isVulnerable: false,
        error: `Network error: ${error.message}`,
        isUnknown: true
      };
    }
    
    // Generic error handling
    return {
      isVulnerable: false,
      error: `Failed to check vulnerabilities: ${error.message}`,
      isUnknown: true
    };
  }
}