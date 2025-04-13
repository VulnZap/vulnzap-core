import fs from 'fs/promises';
import path from 'path';
import CONFIG from './serviceConfig.js';

interface NvdVulnerability {
  cve: {
    id: string;
    descriptions: Array<{
      lang: string;
      value: string;
    }>;
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData: {
          baseScore: number;
          baseSeverity: string;
          vectorString: string;
        };
      }>;
      cvssMetricV30?: Array<{
        cvssData: {
          baseScore: number;
          baseSeverity: string;
          vectorString: string;
        };
      }>;
      cvssMetricV2?: Array<{
        cvssData: {
          baseScore: number;
          baseSeverity: string;
          vectorString: string;
        };
      }>;
    };
    references: Array<{
      url: string;
    }>;
    configurations: Array<{
      nodes: Array<{
        operator: string;
        cpeMatch: Array<{
          vulnerable: boolean;
          criteria: string;
          versionEndExcluding?: string;
          versionEndIncluding?: string;
          versionStartExcluding?: string;
          versionStartIncluding?: string;
        }>;
      }>;
    }>;
  };
}

import { VulnerabilityResult } from './github-advisory-source.js';

export default class NvdSource {
  private readonly API_URL: string;
  private readonly CACHE_TTL: number;
  private readonly cachePath: string;
  private isInitialized: boolean = false;

  constructor(options: { apiUrl?: string; cacheTtl?: number } = {}) {
    this.API_URL = options.apiUrl || CONFIG.SERVICE_ENDPOINTS.NVD_API || 'https://services.nvd.nist.gov/rest/json/cves/2.0';
    this.CACHE_TTL = options.cacheTtl || 24 * 60 * 60; // 24 hours in seconds
    this.cachePath = path.join(CONFIG.DATA_PATHS.CACHE_DIR, 'nvd-advisories');
  }

  async initialize(): Promise<boolean> {
    if (this.isInitialized) return true;
    
    try {
      // Create cache directory if it doesn't exist
      await fs.mkdir(this.cachePath, { recursive: true });

      // Test the connection with a simple query
      await this.makeApiRequest('?resultsPerPage=1');
      this.isInitialized = true;
      return true;
    } catch (error) {
      console.error('Failed to initialize NVD source:', error);
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
      console.error('Error saving to NVD cache:', error);
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
              console.error(`Failed to delete NVD cache file ${file}:`, err)
            )
          )
        );
      }
    } catch (error) {
      console.error('Error clearing NVD cache:', error);
    }
  }

  private async makeApiRequest(endpoint: string): Promise<any> {
    try {
      const response = await fetch(`${this.API_URL}${endpoint}`, {
        headers: {
          'apiKey': CONFIG.API_KEYS.NVD
        }
      });

      if (!response.ok) {
        throw new Error(`NVD API error: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error making NVD API request:', error);
      throw error;
    }
  }

  private determineSeverity(vuln: NvdVulnerability): string {
    // Try CVSS v3.1 first
    if (vuln.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity) {
      return vuln.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity.toLowerCase();
    }
    
    // Then try CVSS v3.0
    if (vuln.cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity) {
      return vuln.cve.metrics.cvssMetricV30[0].cvssData.baseSeverity.toLowerCase();
    }
    
    // Finally try CVSS v2
    if (vuln.cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseSeverity) {
      return vuln.cve.metrics.cvssMetricV2[0].cvssData.baseSeverity.toLowerCase();
    }
    
    return 'medium';
  }

  private processNvdResults(results: NvdVulnerability[], packageName: string, version: string, ecosystem: string): VulnerabilityResult {
    if (!results || results.length === 0) {
      return {
        isVulnerable: false,
        message: 'No vulnerabilities found',
        sources: ['nvd']
      };
    }

    const advisories = results.map(vuln => ({
      id: vuln.cve.id,
      title: vuln.cve.descriptions.find(d => d.lang === 'en')?.value || 'Unknown vulnerability',
      severity: this.determineSeverity(vuln),
      cve_id: vuln.cve.id,
      description: vuln.cve.descriptions.find(d => d.lang === 'en')?.value || 'No description available',
    }));

    // Extract fixed versions from the first vulnerability
    const fixedVersions: string[] = [];
    if (results[0].cve.configurations && results[0].cve.configurations.length > 0) {
      results[0].cve.configurations.forEach(config => {
        config.nodes.forEach(node => {
          node.cpeMatch.forEach(match => {
            if (match.versionEndExcluding) {
              fixedVersions.push(match.versionEndExcluding);
            }
            if (match.versionEndIncluding) {
              fixedVersions.push(match.versionEndIncluding);
            }
          });
        });
      });
    }

    return {
      isVulnerable: true,
      advisories,
      fixedVersions: fixedVersions.length > 0 ? fixedVersions : undefined,
      sources: ['nvd']
    };
  }

  async findVulnerabilities(packageName: string, version: string, ecosystem: string, options: { refresh?: boolean } = {}): Promise<VulnerabilityResult> {
    try {
      if (!this.isInitialized) {
        await this.initialize();
      }
      
      const cacheKey = `nvd:${ecosystem}:${packageName}:${version}`;
      
      if (!options.refresh) {
        const cached = await this._getFromCache<VulnerabilityResult>(cacheKey);
        if (cached) {
          return cached;
        }
      } else {
        // Clear existing cache if refresh is requested
        await this._clearCache(cacheKey);
      }
      
      // Construct CPE string for the package
      const cpeString = `cpe:2.3:a:${packageName}:${packageName}:${version}:*:*:*:*:*:*:*`;
      
      const results = await this.makeApiRequest(`?cpeName=${encodeURIComponent(cpeString)}`);
      
      const vulnerabilityResult = this.processNvdResults(results.vulnerabilities || [], packageName, version, ecosystem);
      
      await this._saveToCache(cacheKey, vulnerabilityResult, this.CACHE_TTL);
      
      return vulnerabilityResult;
    } catch (error: any) {
      console.error(`Error finding NVD vulnerabilities for ${packageName}@${version}:`, error);
      return {
        isVulnerable: false,
        error: `Error querying NVD API: ${error.message || 'Unknown error'}`,
        sources: ['nvd']
      };
    }
  }
} 