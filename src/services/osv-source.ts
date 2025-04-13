import fs from 'fs/promises';
import path from 'path';
import CONFIG from './serviceConfig.js';
import { VulnerabilityResult } from './github-advisory-source.js';

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  affected: Array<{
    package: {
      name: string;
      ecosystem: string;
    };
    ranges?: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
      }>;
    }>;
    ecosystem_specific?: {
      severity?: string;
    };
  }>;
  references: Array<{
    type: string;
    url: string;
  }>;
}

export default class OsvSource {
  private readonly API_URL: string;
  private readonly CACHE_TTL: number;
  private readonly cachePath: string;
  private isInitialized: boolean = false;

  constructor(options: { apiUrl?: string; cacheTtl?: number } = {}) {
    this.API_URL = options.apiUrl || 'https://api.osv.dev/v1';
    this.CACHE_TTL = options.cacheTtl || 24 * 60 * 60; // 24 hours in seconds
    this.cachePath = path.join(CONFIG.DATA_PATHS.CACHE_DIR, 'osv-advisories');
  }

  async initialize(): Promise<boolean> {
    if (this.isInitialized) return true;
    
    try {
      // Create cache directory if it doesn't exist
      await fs.mkdir(this.cachePath, { recursive: true });

      // Test the connection with a simple query
      await this.makeApiRequest('/query', {
        package: {
          name: 'test',
          ecosystem: 'npm'
        },
        version: '1.0.0'
      });
      
      this.isInitialized = true;
      return true;
    } catch (error) {
      console.error('Failed to initialize OSV source:', error);
      return false;
    }
  }

  /**
   * Save data to cache file
   * @private
   */
  private async _saveToCache<T>(key: string, data: T, ttl: number = this.CACHE_TTL): Promise<void> {
    try {
      const cacheFile = path.join(this.cachePath, `${key.replace(/[^a-zA-Z0-9]/g, '_')}.json`);
      const cacheData = {
        data,
        expires: Date.now() + (ttl * 1000),
        created: Date.now()
      };
      await fs.writeFile(cacheFile, JSON.stringify(cacheData, null, 2));
    } catch (error) {
      console.error('Error saving to OSV cache:', error);
    }
  }

  /**
   * Get data from cache
   * @private
   */
  private async _getFromCache<T>(key: string): Promise<T | null> {
    try {
      const cacheFile = path.join(this.cachePath, `${key.replace(/[^a-zA-Z0-9]/g, '_')}.json`);
      const data = JSON.parse(await fs.readFile(cacheFile, 'utf8'));

      // Check if cache has expired
      if (data.expires < Date.now()) {
        await fs.unlink(cacheFile);
        return null;
      }

      return data.data as T;
    } catch (error) {
      return null;
    }
  }

  /**
   * Clear cache for specific key or all cache
   * @private
   */
  private async _clearCache(key?: string): Promise<void> {
    try {
      if (key) {
        const cacheFile = path.join(this.cachePath, `${key.replace(/[^a-zA-Z0-9]/g, '_')}.json`);
        await fs.unlink(cacheFile).catch(() => {});
      } else {
        const files = await fs.readdir(this.cachePath);
        await Promise.all(
          files.map(file => 
            fs.unlink(path.join(this.cachePath, file)).catch(err => 
              console.error(`Failed to delete OSV cache file ${file}:`, err)
            )
          )
        );
      }
    } catch (error) {
      console.error('Error clearing OSV cache:', error);
    }
  }

  private async makeApiRequest(endpoint: string, body: any): Promise<any> {
    try {
      const response = await fetch(`${this.API_URL}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
      });

      if (!response.ok) {
        return {
          vulnerabilities: [],
          isVulnerable: false,
          message: 'No vulnerabilities found',
          sources: ['osv']
        }
      }

      return await response.json();
    } catch (error) {
      console.error('Error making OSV API request:', error);
      throw error;
    }
  }

  private determineSeverity(vuln: OsvVulnerability): string {
    // Try to get from ecosystem-specific severity
    for (const affected of vuln.affected) {
      if (affected.ecosystem_specific?.severity) {
        return affected.ecosystem_specific.severity.toLowerCase();
      }
    }
    
    // Default to medium if we can't determine
    return 'medium';
  }

  private extractCveId(vuln: OsvVulnerability): string | undefined {
    // Look for CVE in references
    for (const ref of vuln.references) {
      if (ref.type === 'ADVISORY' && ref.url.includes('cve.mitre.org')) {
        const match = ref.url.match(/CVE-\d{4}-\d+/);
        if (match) {
          return match[0];
        }
      }
    }
    return undefined;
  }

  private processOsvResults(results: OsvVulnerability[], packageName: string, version: string, ecosystem: string): VulnerabilityResult {
    if (!results || results.length === 0) {
      return {
        isVulnerable: false,
        message: 'No vulnerabilities found',
        sources: ['osv']
      };
    }

    const advisories = results.map(vuln => ({
      id: vuln.id,
      title: vuln.summary || 'Unknown vulnerability',
      severity: this.determineSeverity(vuln),
      cve_id: this.extractCveId(vuln),
      description: vuln.details || 'No details available',
    }));

    // Extract fixed versions from the first vulnerability
    const fixedVersions: string[] = [];
    if (results[0].affected && results[0].affected.length > 0) {
      results[0].affected.forEach(affected => {
        if (affected.ranges) {
          affected.ranges.forEach(range => {
            if (range.type === 'GIT') {
              range.events.forEach(event => {
                if (event.fixed) {
                  fixedVersions.push(event.fixed);
                }
              });
            }
          });
        }
      });
    }

    return {
      isVulnerable: true,
      advisories,
      fixedVersions: fixedVersions.length > 0 ? fixedVersions : undefined,
      sources: ['osv']
    };
  }

  async findVulnerabilities(packageName: string, version: string, ecosystem: string, options: { refresh?: boolean } = {}): Promise<VulnerabilityResult> {
    try {
      if (!this.isInitialized) {
        await this.initialize();
      }
      
      const cacheKey = `osv:${ecosystem}:${packageName}:${version}`;
      
      if (!options.refresh) {
        const cached = await this._getFromCache<VulnerabilityResult>(cacheKey);
        if (cached) {
          return cached;
        }
      } else {
        // Clear existing cache if refresh is requested
        await this._clearCache(cacheKey);
      }
      
      const results = await this.makeApiRequest('/query', {
        package: {
          name: packageName,
          ecosystem: ecosystem
        },
        version
      });
      
      const vulnerabilityResult = this.processOsvResults(results.vulns || [], packageName, version, ecosystem);
      
      await this._saveToCache(cacheKey, vulnerabilityResult, this.CACHE_TTL);
      
      return vulnerabilityResult;
    } catch (error: any) {
      console.error(`Error finding OSV vulnerabilities for ${packageName}@${version}:`, error);
      return {
        isVulnerable: false,
        error: `Error querying OSV API: ${error.message || 'Unknown error'}`,
        sources: ['osv']
      };
    }
  }
} 