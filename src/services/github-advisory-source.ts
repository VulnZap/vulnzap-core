import fs from 'fs/promises';
import path from 'path';
import CONFIG from './serviceConfig.js';

interface GitHubAdvisory {
  id: number;
  ghsa_id: string;
  cve_id: string | null;
  url: string;
  html_url: string;
  repository_advisory_url: string | null;
  summary: string;
  description: string;
  type: string;
  severity: string;
  source_code_location: string | null;
  identifiers: Array<{
    type: string;
    value: string;
  }>;
  references: string[];
  published_at: string;
  updated_at: string;
  github_reviewed_at: string | null;
  nvd_published_at: string | null;
  withdrawn_at: string | null;
  vulnerabilities: Array<{
    package: {
      ecosystem: string;
      name: string;
    };
    first_patched_version: string | null;
    vulnerable_version_range: string;
    vulnerable_functions: string[] | null;
  }>;
  cvss: {
    vector_string: string;
    score: number;
  } | null;
  cvss_severities: {
    cvss_v3: {
      vector_string: string;
      score: number;
    } | null;
    cvss_v4: {
      vector_string: string;
      score: number;
    } | null;
  } | null;
  cwes: Array<{
    cwe_id: string;
    name: string;
  }> | null;
  epss: Array<{
    percentage: number;
    percentile: string;
  }> | null;
  credits: Array<{
    user: {
      login: string;
      id: number;
      node_id: string;
      avatar_url: string;
      gravatar_id: string;
      url: string;
      html_url: string;
      followers_url: string;
      following_url: string;
      gists_url: string;
      starred_url: string;
      subscriptions_url: string;
      organizations_url: string;
      repos_url: string;
      events_url: string;
      received_events_url: string;
      type: string;
      site_admin: boolean;
    };
    type: string;
  }> | null;
}

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

export default class GitHubAdvisorySource {
  private readonly CACHE_TTL = 24 * 60 * 60; // 24 hours in seconds
  private isInitialized: boolean = false;
  private cachePath: string;

  constructor() {
    this.cachePath = path.join(CONFIG.DATA_PATHS.CACHE_DIR, 'github-advisories');
    this.initialize();
  }

  async initialize(): Promise<boolean> {
    if (this.isInitialized) return true;
    
    try {
      // Create cache directory if it doesn't exist
      await fs.mkdir(this.cachePath, { recursive: true });
      
      this.isInitialized = true;
      return true;
    } catch (error) {
      console.error('Failed to initialize GitHub Advisory Source:', error);
      return false;
    }
  }

  /**
   * Save data to cache file
   * @private
   */
  private async _saveToCache(key: string, data: any, ttl: number = this.CACHE_TTL): Promise<void> {
    try {
      const cacheFile = path.join(this.cachePath, `${key.replace(/[^a-zA-Z0-9]/g, '_')}.json`);
      const cacheData = {
        data,
        expires: Date.now() + (ttl * 1000),
        created: Date.now()
      };
      await fs.writeFile(cacheFile, JSON.stringify(cacheData, null, 2));
    } catch (error) {
      console.error('Error saving to cache:', error);
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
              console.error(`Failed to delete cache file ${file}:`, err)
            )
          )
        );
      }
    } catch (error) {
      console.error('Error clearing cache:', error);
    }
  }

  private async makeApiRequest(endpoint: string = ''): Promise<any> {
    try {
      const response = await fetch(`${CONFIG.SERVICE_ENDPOINTS.GITHUB_ADVISORY}`, {
        headers: {
          'Accept': 'application/vnd.github+json',
          'Authorization': `Bearer ${CONFIG.API_KEYS.GITHUB}`,
          'X-GitHub-Api-Version': '2022-11-28'
        }
      });

      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.statusText}`);
      }

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Error making GitHub API request:', error);
      throw error;
    }
  }

  async getAllAdvisoriesForEcosystem(ecosystem: string): Promise<GitHubAdvisory[]> {
    const cacheKey = `github:advisories:${ecosystem}`;
    
    // Try to get from cache first
    const cached = await this._getFromCache<GitHubAdvisory[]>(cacheKey);
    if (cached) {
      return cached;
    }

    // Fetch all advisories
    const advisories = await this.makeApiRequest();

    // Filter advisories for the specified ecosystem
    const ecosystemAdvisories = advisories.filter((advisory: GitHubAdvisory) => 
      advisory.vulnerabilities.some(vuln => 
        vuln.package.ecosystem.toLowerCase() === ecosystem.toLowerCase()
      )
    );

    // Cache the results
    await this._saveToCache(cacheKey, ecosystemAdvisories, this.CACHE_TTL);

    return ecosystemAdvisories;
  }

  private processAdvisoryResults(results: GitHubAdvisory[], packageName: string, version: string, ecosystem: string): VulnerabilityResult {
    const advisories = results.map(advisory => ({
      id: advisory.ghsa_id,
      title: advisory.summary,
      severity: advisory.severity.toLowerCase(),
      cve_id: advisory.cve_id || undefined,
      description: advisory.description,
    }));

    // Extract fixed versions from the first advisory
    const fixedVersions: string[] = [];
    if (results[0].vulnerabilities && results[0].vulnerabilities.length > 0) {
      results[0].vulnerabilities.forEach(vuln => {
        if (vuln.first_patched_version) {
          fixedVersions.push(vuln.first_patched_version);
        }
      });
    }

    return {
      isVulnerable: true,
      advisories,
      fixedVersions: fixedVersions.length > 0 ? fixedVersions : undefined,
      sources: ['github']
    };
  }

  async findVulnerabilities(packageName: string, version: string, ecosystem: string, options: { refresh?: boolean } = {}): Promise<VulnerabilityResult> {
    try {
      if (!this.isInitialized) {
        await this.initialize();
      }
      
      const cacheKey = `github:${ecosystem}:${packageName}:${version}`;
      
      if (!options.refresh) {
        const cached = await this._getFromCache<VulnerabilityResult>(cacheKey);
        if (cached) {
          return cached;
        }
      } else {
        // Clear existing cache if refresh is requested
        await this._clearCache(cacheKey);
      }

      const existingAdvisories = await this.getAllAdvisoriesForEcosystem(ecosystem);

      const advisories = existingAdvisories.filter((advisory: GitHubAdvisory) => 
        advisory.vulnerabilities.some(vuln => 
          vuln.package.ecosystem.toLowerCase() === ecosystem.toLowerCase() &&
          vuln.package.name.toLowerCase() === packageName.toLowerCase()
        )
      );

      if (advisories.length === 0) {
        const result = {
          isVulnerable: false,
          message: 'No vulnerabilities found',
          sources: ['github']
        };  
        await this._saveToCache(cacheKey, result, this.CACHE_TTL);
        return result;
      }

      const newAdvisories = await this.makeApiRequest();
      
      // Filter advisories for the specified ecosystem and package
      const relevantAdvisories = newAdvisories.filter((advisory: GitHubAdvisory) => 
        advisory.vulnerabilities.some(vuln => 
          vuln.package.ecosystem.toLowerCase() === ecosystem.toLowerCase() &&
          vuln.package.name.toLowerCase() === packageName.toLowerCase()
        )
      );
      
      if (relevantAdvisories.length === 0) {
        const result = {
          isVulnerable: false,
          message: 'No vulnerabilities found',
          sources: ['github']
        };
        await this._saveToCache(cacheKey, result, this.CACHE_TTL);
        return result;
      }

      const vulnerabilityResult = this.processAdvisoryResults(relevantAdvisories, packageName, version, ecosystem);
      
      await this._saveToCache(cacheKey, vulnerabilityResult, this.CACHE_TTL);
      
      return vulnerabilityResult;
    } catch (error: any) {
      console.error(`Error finding GitHub vulnerabilities for ${packageName}@${version}:`, error);
      return {
        isVulnerable: false,
        error: `Error querying GitHub API: ${error.message || 'Unknown error'}`,
        sources: ['github']
      };
    }
  }
} 