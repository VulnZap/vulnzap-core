import fs from 'fs/promises';
import path from 'path';
import CONFIG from './serviceConfig.js';
import { VulnerabilityResult } from './github-advisory-source.js';

interface OwaspVulnerability {
  id: string;
  title: string;
  description: string;
  severity: string;
  cwe_id?: string;
  references: Array<{
    url: string;
    title?: string;
  }>;
  recommendations?: string[];
  affected_versions?: Array<{
    package: string;
    ecosystem: string;
    version_range: string;
    fixed_version?: string;
  }>;
  cvss?: {
    score: number;
    vector: string;
  };
}

export default class OwaspSource {
  private readonly API_URL: string;
  private readonly CACHE_TTL: number;
  private readonly cachePath: string;
  private isInitialized: boolean = false;

  constructor(options: { apiUrl?: string; cacheTtl?: number } = {}) {
    this.API_URL = options.apiUrl || CONFIG.SERVICE_ENDPOINTS.OWASP_API || 'https://api.owasp.org/v1';
    this.CACHE_TTL = options.cacheTtl || 24 * 60 * 60; // 24 hours in seconds
    this.cachePath = path.join(CONFIG.DATA_PATHS.CACHE_DIR, 'owasp-advisories');
  }

  async initialize(): Promise<boolean> {
    if (this.isInitialized) return true;
    
    try {
      // Create cache directory if it doesn't exist
      await fs.mkdir(this.cachePath, { recursive: true });

      // Test the connection with a simple query
      await this.makeApiRequest('/health');
      
      this.isInitialized = true;
      return true;
    } catch (error) {
      console.error('Failed to initialize OWASP source:', error);
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
      console.error('Error saving to OWASP cache:', error);
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
              console.error(`Failed to delete OWASP cache file ${file}:`, err)
            )
          )
        );
      }
    } catch (error) {
      console.error('Error clearing OWASP cache:', error);
    }
  }

  private async makeApiRequest(endpoint: string, params: Record<string, string> = {}): Promise<any> {
    try {
      const queryString = new URLSearchParams(params).toString();
      const url = `${this.API_URL}${endpoint}${queryString ? '?' + queryString : ''}`;

      const response = await fetch(url, {
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${CONFIG.API_KEYS.OWASP}`
        }
      });

      if (!response.ok) {
        throw new Error(`OWASP API error: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error making OWASP API request:', error);
      throw error;
    }
  }

  private determineSeverity(vuln: OwaspVulnerability): string {
    if (vuln.severity) {
      return vuln.severity.toLowerCase();
    }
    
    // If no severity is provided but CVSS score is available
    if (vuln.cvss?.score) {
      const score = vuln.cvss.score;
      if (score >= 9.0) return 'critical';
      if (score >= 7.0) return 'high';
      if (score >= 4.0) return 'medium';
      return 'low';
    }
    
    return 'medium'; // Default severity
  }

  private processOwaspResults(results: OwaspVulnerability[], packageName: string, version: string, ecosystem: string): VulnerabilityResult {
    if (!results || results.length === 0) {
      return {
        isVulnerable: false,
        message: 'No vulnerabilities found',
        sources: ['owasp']
      };
    }

    const advisories = results.map(vuln => ({
      id: vuln.id,
      title: vuln.title,
      severity: this.determineSeverity(vuln),
      cwe_id: vuln.cwe_id,
      description: vuln.description,
      recommendations: vuln.recommendations,
      references: vuln.references.map(ref => ref.url)
    }));

    // Extract fixed versions
    const fixedVersions = results
      .flatMap(vuln => vuln.affected_versions || [])
      .filter(affected => 
        affected.package === packageName && 
        affected.ecosystem === ecosystem &&
        affected.fixed_version
      )
      .map(affected => affected.fixed_version as string);

    return {
      isVulnerable: true,
      advisories,
      fixedVersions: fixedVersions.length > 0 ? [...new Set(fixedVersions)] : undefined,
      sources: ['owasp']
    };
  }

  async findVulnerabilities(packageName: string, version: string, ecosystem: string, options: { refresh?: boolean } = {}): Promise<VulnerabilityResult> {
    try {
      if (!this.isInitialized) {
        await this.initialize();
      }
      
      const cacheKey = `owasp:${ecosystem}:${packageName}:${version}`;
      
      if (!options.refresh) {
        const cached = await this._getFromCache<VulnerabilityResult>(cacheKey);
        if (cached) {
          return cached;
        }
      } else {
        // Clear existing cache if refresh is requested
        await this._clearCache(cacheKey);
      }
      
      // Query OWASP database for vulnerabilities
      const results = await this.makeApiRequest('/vulnerabilities/search', {
        package: packageName,
        ecosystem: ecosystem,
        version: version
      });
      
      const vulnerabilityResult = this.processOwaspResults(results.vulnerabilities || [], packageName, version, ecosystem);
      
      await this._saveToCache(cacheKey, vulnerabilityResult, this.CACHE_TTL);
      
      return vulnerabilityResult;
    } catch (error: any) {
      console.error(`Error finding OWASP vulnerabilities for ${packageName}@${version}:`, error);
      return {
        isVulnerable: false,
        error: `Error querying OWASP API: ${error.message || 'Unknown error'}`,
        sources: ['owasp']
      };
    }
  }
} 