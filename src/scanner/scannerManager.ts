/**
 * Scanner Manager
 * 
 * Central system for coordinating vulnerability scanning across multiple package ecosystems.
 * Handles scheduling, executing, and aggregating scan results.
 */

import { EventEmitter } from 'events';
import packageParsers from '../utils/package-parsers.js';
import versionParsers from '../utils/version-parsers.js';
import CONFIG from '../services/serviceConfig.js';
import fs from 'fs/promises'

// Import data sources
import GitHubAdvisorySource from '../services/github-advisory-source.js';
import NvdSource from '../services/nvd-source.js';
import OsvSource from '../services/osv-source.js';
// import OwaspSource from '../services/owasp-source.js';

interface ScannerManagerOptions {
    cachePath: any,
    concurrency: any,
    timeout: any
}

interface DataSources {
    github: GitHubAdvisorySource,
    nvd: NvdSource,
    osv: OsvSource,
    // owasp: OwaspSource
}

/**
 * Scanner Manager class
 * 
 * Coordinates vulnerability scanning across multiple ecosystems
 */
export class ScannerManager extends EventEmitter {
    private options: ScannerManagerOptions;
    private dataSources: DataSources;
    private activeScans: any;
    private ecosystemScanners: any;
    private resultsCache: any;
    
    constructor(options?: ScannerManagerOptions) {
        super();

        // Configure options
        this.options = {
            cachePath: options?.cachePath || CONFIG.DATA_PATHS.CACHE_DIR,
            concurrency: options?.concurrency || 3,
            timeout: options?.timeout || 60000
        };

        // Initialize data sources
        this.dataSources = {
            github: new GitHubAdvisorySource(),
            nvd: new NvdSource(),
            osv: new OsvSource(),
            // owasp: new OwaspSource()
        };

        // Track active scans
        this.activeScans = new Map();

        // Initialize ecosystem scanners
        this.ecosystemScanners = {};

        // Initialize results cache
        this.resultsCache = new Map();

        this._init();
    }

    /**
     * Initialize scanner manager
     * @private
     */
    async _init() {
        try {
            // Create cache directory if it doesn't exist
            await fs.mkdir(this.options.cachePath, { recursive: true });

            // Initialize cache with empty data
            const cacheFile = `${this.options.cachePath}/cache.json`;
            const emptyData = JSON.stringify({ initialized: true, lastUpdated: new Date().toISOString() });
            await fs.writeFile(cacheFile, emptyData);

            // Load ecosystem scanners
            this._loadEcosystemScanners();

            // Initialize data sources
            await this._initializeDataSources();

            this.emit('ready');
        } catch (error) {
            console.error('Error initializing ScannerManager:', error);
            this.emit('error', error);
        }
    }

    /**
     * Load ecosystem-specific scanners
     * @private
     */
    _loadEcosystemScanners() {
        // Load only enabled ecosystems from config
        for (const ecosystem of CONFIG.ENABLED_ECOSYSTEMS) {
            try {
                // Dynamic import would be better but for simplicity we'll use require
                const ecosystemConfig = CONFIG.ECOSYSTEMS[ecosystem];

                if (!ecosystemConfig) {
                    console.warn(`No configuration found for ecosystem: ${ecosystem}`);
                    continue;
                }

                // Create scanner instance for this ecosystem
                this.ecosystemScanners[ecosystem] = {
                    config: ecosystemConfig,
                    scan: this._createEcosystemScannerFn(ecosystem)
                };
            } catch (error) {
                console.error(`Failed to load scanner for ecosystem: ${ecosystem}`, error);
            }
        }
    }

    /**
     * Initialize all data sources
     * @private
     */
    async _initializeDataSources() {
        const initPromises = [] as any[];

        for (const [name, source] of Object.entries(this.dataSources)) {
            initPromises.push(
                source.initialize().catch(error => {
                    console.error(`Failed to initialize data source: ${name}`, error);
                    return null;
                })
            );
        }

        await Promise.all(initPromises);
    }

    /**
     * Create a scanner function for a specific ecosystem
     * @private
     * @param {string} ecosystem - Ecosystem name
     * @returns {Function} - Scanner function for the ecosystem
     */
    _createEcosystemScannerFn(ecosystem) {
        return async (packageName, version, options = {} as any) => {
            try {
                // Check cache first
                const cacheKey = `${ecosystem}:${packageName}:${version}`;

                if (this.resultsCache.has(cacheKey) && !options.noCache) {
                    return this.resultsCache.get(cacheKey);
                }

                // Collect results from all data sources
                const results = [] as any[];

                // Query each data source
                const sourcePromises = Object.entries(this.dataSources).map(async ([sourceName, source]) => {
                    try {
                        const sourceResults = await source.findVulnerabilities(
                            packageName,
                            version,
                            ecosystem,
                            options
                        );

                        if (sourceResults && sourceResults.length > 0) {
                            // Add source information
                            sourceResults.forEach(result => {
                                result.source = sourceName;
                                results.push(result);
                            });
                        }
                    } catch (error) {
                        console.error(`Error from ${sourceName} data source:`, error);
                    }
                });

                await Promise.all(sourcePromises);

                // De-duplicate results based on vulnerability ID
                const uniqueResults = this._deduplicateResults(results);

                // Cache results
                if (!options.noCache) {
                    this.resultsCache.set(cacheKey, uniqueResults);
                }

                return uniqueResults;
            } catch (error) {
                console.error(`Error scanning ${ecosystem} package ${packageName}@${version}:`, error);
                return [];
            }
        };
    }

    /**
     * Remove duplicate vulnerability reports
     * @private
     * @param {Array} results - Vulnerability results
     * @returns {Array} - Deduplicated results
     */
    _deduplicateResults(results) {
        const uniqueMap = new Map();

        for (const result of results) {
            const id = result.id || result.cve || result.ghsa || JSON.stringify(result);

            // If we already have this vulnerability, merge any additional info
            if (uniqueMap.has(id)) {
                const existing = uniqueMap.get(id);
                uniqueMap.set(id, {
                    ...existing,
                    ...result,
                    // Combine sources
                    source: Array.isArray(existing.source)
                        ? [...new Set([...existing.source, result.source])]
                        : [existing.source, result.source],
                    // Use the most severe CVSS score
                    cvss: Math.max(existing.cvss || 0, result.cvss || 0),
                    references: [...(existing.references || []), ...(result.references || [])].filter((v, i, a) => a.indexOf(v) === i)
                });
            } else {
                uniqueMap.set(id, {
                    ...result,
                    references: result.references || []
                });
            }
        }

        return Array.from(uniqueMap.values());
    }

    /**
     * Save results to cache file
     * @private
     * @param {string} key - Cache key
     * @param {any} data - Data to cache
     * @param {number} ttl - Time to live in seconds
     */
    private async _saveToCache(key: string, data: any, ttl: number = 24 * 60 * 60) {
        try {
            const cacheFile = `${this.options.cachePath}/${key.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
            const cacheData = {
                data,
                expires: Date.now() + (ttl * 1000),
                created: Date.now()
            };
            await fs.writeFile(cacheFile, JSON.stringify(cacheData));
            this.resultsCache.set(key, data);
        } catch (error) {
            console.error('Error saving to cache:', error);
        }
    }

    /**
     * Get data from cache
     * @private
     * @param {string} key - Cache key
     * @returns {Promise<any>} - Cached data or null
     */
    private async _getFromCache(key: string): Promise<any> {
        try {
            // Check memory cache first
            if (this.resultsCache.has(key)) {
                return this.resultsCache.get(key);
            }

            // Check file cache
            const cacheFile = `${this.options.cachePath}/${key.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
            const data = JSON.parse(await fs.readFile(cacheFile, 'utf8'));

            // Check if cache has expired
            if (data.expires < Date.now()) {
                await fs.unlink(cacheFile);
                return null;
            }

            // Update memory cache
            this.resultsCache.set(key, data.data);
            return data.data;
        } catch (error) {
            return null;
        }
    }

    /**
     * Scan a single package for vulnerabilities
     * 
     * @param {string} packageName - Package name
     * @param {string} version - Package version
     * @param {string} ecosystem - Package ecosystem (npm, pip, etc.)
     * @param {Object} options - Scan options
     * @returns {Promise<Array>} - Vulnerability scan results
     */
    async scanPackage(packageName: string, version: string, ecosystem: string, options: any = {}): Promise<any> {
        try {
            // Check cache first
            const cacheKey = `scan:${ecosystem}:${packageName}:${version}`;
            const cachedResult = await this._getFromCache(cacheKey);
            
            if (cachedResult && !options.force) {
                return cachedResult;
            }

            // Get vulnerabilities from all sources
            const vulnerabilities = await Promise.all(
                Object.values(this.dataSources).map(source => 
                    source.findVulnerabilities(packageName, version, ecosystem)
                )
            );

            // Combine and deduplicate results
            const allVulnerabilities = vulnerabilities.flat();
            const uniqueVulnerabilities = this._deduplicateResults(allVulnerabilities).filter(vuln => vuln.isVulnerable);

            // Cache the results
            await this._saveToCache(cacheKey, uniqueVulnerabilities, 24 * 60 * 60); // Cache for 24 hours

            return uniqueVulnerabilities;
        } catch (error) {
            console.error(`Error scanning package ${packageName}@${version}:`, error);
            throw error;
        }
    }

    /**
     * Scan a directory for vulnerabilities in all detected ecosystems
     * 
     * @param {string} directory - Directory to scan
     * @param {Object} options - Scan options
     * @returns {Promise<Object>} - Scan results by ecosystem
     */
    async scanDirectory(directory, options = {} as any) {
        try {
            // Detect ecosystems in the directory
            const detectedEcosystems = await packageParsers.detectEcosystems(directory);

            if (detectedEcosystems.length === 0) {
                return { error: 'No supported ecosystems detected in the directory' };
            }

            const results = {};

            // Scan each detected ecosystem
            for (const { ecosystem, manifestPath } of detectedEcosystems) {
                // Check if ecosystem is supported
                if (!this.ecosystemScanners[ecosystem]) {
                    results[ecosystem] = { error: `Ecosystem ${ecosystem} is not supported` };
                    continue;
                }

                // Parse dependencies
                const dependencies = await packageParsers.parseDependencies(manifestPath, ecosystem);

                if (dependencies.length === 0) {
                    results[ecosystem] = { error: `No dependencies found for ${ecosystem}` };
                    continue;
                }

                // Scan each dependency
                const ecosystemResults = [] as any[];

                // Use batch processing if enabled in options
                if (options.batch) {
                    const batchSize = options.batchSize || 10;
                    const batches = [] as any[];

                    // Create batches of dependencies
                    for (let i = 0; i < dependencies.length; i += batchSize) {
                        batches.push(dependencies.slice(i, i + batchSize));
                    }

                    // Process batches sequentially to avoid overwhelming the system
                    for (const batch of batches) {
                        const batchPromises = batch.map(dep =>
                            this.scanPackage(dep.name, dep.version, ecosystem, options)
                                .then(vulns => ({ package: dep.name, version: dep.version, vulnerabilities: vulns }))
                                .catch(error => ({
                                    package: dep.name,
                                    version: dep.version,
                                    error: error.message
                                }))
                        );

                        const batchResults = await Promise.all(batchPromises);
                        ecosystemResults.push(...batchResults);

                        // Small delay between batches to avoid rate limits
                        if (batches.length > 1) {
                            await new Promise(resolve => setTimeout(resolve, 1000));
                        }
                    }
                } else {
                    // Process each dependency sequentially
                    for (const dep of dependencies) {
                        try {
                            const vulns = await this.scanPackage(dep.name, dep.version, ecosystem, options);
                            ecosystemResults.push({
                                package: dep.name,
                                version: dep.version,
                                vulnerabilities: vulns
                            });
                        } catch (error: any) {
                            ecosystemResults.push({
                                package: dep.name,
                                version: dep.version,
                                error: error.message
                            });
                        }
                    }
                }

                results[ecosystem] = {
                    manifestPath,
                    dependencies: dependencies.length,
                    results: ecosystemResults
                };
            }

            return {
                directory,
                timestamp: new Date().toISOString(),
                results
            };
        } catch (error: any) {
            console.error(`Error scanning directory ${directory}:`, error);
            return { error: error.message };
        }
    }

    /**
     * Scan multiple packages in batch
     * 
     * @param {Array<{name: string, version: string, ecosystem: string}>} packages - Packages to scan
     * @param {Object} options - Scan options
     * @returns {Promise<Array>} - Scan results
     */
    async batchScan(packages, options = {} as any) {
        const batchSize = options.batchSize || 10;
        const results = [] as any;

        // Group packages by ecosystem for more efficient scanning
        const packagesByEcosystem = {} as {
            [ecosystem: string]: Array<{ name: string, version: string, ecosystem: string }>
        };

        for (const pkg of packages) {
            if (!packagesByEcosystem[pkg.ecosystem]) {
                packagesByEcosystem[pkg.ecosystem] = [];
            }
            packagesByEcosystem[pkg.ecosystem].push(pkg);
        }

        // Process each ecosystem
        for (const [ecosystem, ecosystemPackages] of Object.entries(packagesByEcosystem)) {
            // Check if ecosystem is supported
            if (!this.ecosystemScanners[ecosystem]) {
                for (const pkg of ecosystemPackages) {
                    results.push({
                        package: pkg.name,
                        version: pkg.version,
                        ecosystem,
                        error: `Ecosystem ${ecosystem} is not supported`
                    });
                }
                continue;
            }

            // Create batches of packages
            const batches = [] as any;
            for (let i = 0; i < ecosystemPackages.length; i += batchSize) {
                batches.push(ecosystemPackages.slice(i, i + batchSize));
            }

            // Process batches sequentially
            for (const batch of batches) {
                const batchPromises = batch.map(pkg =>
                    this.scanPackage(pkg.name, pkg.version, ecosystem, options)
                        .then(vulns => ({
                            package: pkg.name,
                            version: pkg.version,
                            ecosystem,
                            vulnerabilities: vulns
                        }))
                        .catch(error => ({
                            package: pkg.name,
                            version: pkg.version,
                            ecosystem,
                            error: error.message
                        }))
                );

                const batchResults = await Promise.all(batchPromises);
                results.push(...batchResults);

                // Small delay between batches to avoid rate limits
                if (batches.length > 1) {
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
            }
        }

        return {
            timestamp: new Date().toISOString(),
            totalPackages: packages.length,
            results
        };
    }

    /**
     * Normalize package name according to ecosystem conventions
     * 
     * @private
     * @param {string} packageName - Package name
     * @param {string} ecosystem - Package ecosystem
     * @returns {string} - Normalized package name
     */
    _normalizePackageName(packageName, ecosystem) {
        switch (ecosystem) {
            case 'npm':
                // npm package names are case-sensitive but conventionally lowercase
                return packageName.trim();

            case 'pip':
                // pip package names are case-insensitive and normalized to lowercase
                return packageName.trim().toLowerCase().replace(/[-_.]+/g, '-');

            case 'go':
                // Go module names are typically lowercase and follow URL conventions
                return packageName.trim();

            case 'cargo':
                // Cargo package names are kebab-case
                return packageName.trim().toLowerCase();

            case 'maven':
                // Maven uses groupId:artifactId format
                return packageName.trim();

            case 'composer':
                // Composer uses vendor/package format
                return packageName.trim().toLowerCase();

            case 'nuget':
                // NuGet package names are case-insensitive
                return packageName.trim();

            default:
                return packageName.trim();
        }
    }

    /**
     * Get ecosystem-specific remediation advice
     * 
     * @param {string} packageName - Package name
     * @param {string} version - Vulnerable version
     * @param {string} ecosystem - Package ecosystem
     * @param {Array} vulnerabilities - Vulnerability data
     * @returns {Object} - Remediation advice
     */
    getRemediationAdvice(packageName, version, ecosystem, vulnerabilities) {
        if (!this.ecosystemScanners[ecosystem]) {
            return { error: `Unsupported ecosystem: ${ecosystem}` };
        }

        // Extract all fixed versions from vulnerability data
        const fixedVersions = new Set();

        for (const vuln of vulnerabilities) {
            if (vuln.fixedVersions && vuln.fixedVersions.length > 0) {
                vuln.fixedVersions.forEach(v => fixedVersions.add(v));
            }
        }

        // Find the best version to upgrade to
        let recommendedVersion = null;

        if (fixedVersions.size > 0) {
            // Convert to array and sort by version
            const sortedFixedVersions = Array.from(fixedVersions)
                .filter(v => {
                    const comparisonResult = versionParsers.compareVersions(v as string, version as string, ecosystem);
                    return typeof comparisonResult === 'number' && comparisonResult > 0; // Only newer versions
                })
                .sort((a, b) => {
                    const comparisonResult = versionParsers.compareVersions(a as string, b as string, ecosystem);
                    return typeof comparisonResult === 'number' ? comparisonResult : 0;
                }) as any;

            // Get the lowest fixed version that is higher than current version
            if (sortedFixedVersions.length > 0) {
                recommendedVersion = sortedFixedVersions[0];
            }
        }

        // Get ecosystem-specific update command
        const ecosystemConfig = CONFIG.ECOSYSTEMS[ecosystem];
        const updateCommand = ecosystemConfig?.commands?.update || null;

        let updateInstructions = null;

        if (updateCommand && recommendedVersion) {
            // Format the update command with package name and version
            updateInstructions = updateCommand
                .replace('{package}', packageName)
                .replace('{version}', recommendedVersion);
        }

        return {
            packageName,
            currentVersion: version,
            ecosystem,
            recommendedVersion,
            updateInstructions,
            alternativePackages: [], // Could be enhanced with alternative package suggestions
            notes: recommendedVersion
                ? `Upgrading to version ${recommendedVersion} should resolve ${vulnerabilities.length} known vulnerabilities.`
                : 'No fixed version is currently available. Consider looking for alternative packages or implementing additional security controls.'
        };
    }

    /**
     * Generate a vulnerability report
     * 
     * @param {Object} scanResults - Scan results
     * @param {Object} options - Report options
     * @returns {Object} - Vulnerability report
     */
    generateReport(scanResults, options = {} as any) {
        const summary = {
            scannedPackages: 0,
            vulnerablePackages: 0,
            totalVulnerabilities: 0,
            criticalVulnerabilities: 0,
            highVulnerabilities: 0,
            mediumVulnerabilities: 0,
            lowVulnerabilities: 0,
            ecosystems: {}
        };

        const vulnerablePackages = [] as any;

        // Process all results
        for (const ecosystem in scanResults.results) {
            const ecosystemResults = scanResults.results[ecosystem].results;

            if (!summary.ecosystems[ecosystem]) {
                summary.ecosystems[ecosystem] = {
                    scannedPackages: 0,
                    vulnerablePackages: 0,
                    totalVulnerabilities: 0
                };
            }

            summary.ecosystems[ecosystem].scannedPackages += ecosystemResults.length;
            summary.scannedPackages += ecosystemResults.length;

            for (const packageResult of ecosystemResults) {
                if (packageResult.vulnerabilities && packageResult.vulnerabilities.length > 0) {
                    // Count vulnerable packages
                    summary.vulnerablePackages++;
                    summary.ecosystems[ecosystem].vulnerablePackages++;

                    // Count total vulnerabilities
                    summary.totalVulnerabilities += packageResult.vulnerabilities.length;
                    summary.ecosystems[ecosystem].totalVulnerabilities += packageResult.vulnerabilities.length;

                    // Count vulnerabilities by severity
                    for (const vuln of packageResult.vulnerabilities) {
                        switch (vuln.severity?.toLowerCase()) {
                            case 'critical':
                                summary.criticalVulnerabilities++;
                                break;
                            case 'high':
                                summary.highVulnerabilities++;
                                break;
                            case 'medium':
                                summary.mediumVulnerabilities++;
                                break;
                            case 'low':
                                summary.lowVulnerabilities++;
                                break;
                        }
                    }

                    // Add to vulnerable packages list
                    vulnerablePackages.push({
                        packageName: packageResult.package,
                        version: packageResult.version,
                        ecosystem,
                        vulnerabilities: packageResult.vulnerabilities,
                        // Add remediation advice if requested
                        remediation: options.includeRemediation
                            ? this.getRemediationAdvice(
                                packageResult.package,
                                packageResult.version,
                                ecosystem,
                                packageResult.vulnerabilities
                            )
                            : undefined
                    });
                }
            }
        }

        return {
            timestamp: new Date().toISOString(),
            summary,
            vulnerablePackages: vulnerablePackages.sort((a, b) => {
                // Sort by severity (critical first)
                const aHighestSeverity = this._getHighestSeverity(a.vulnerabilities);
                const bHighestSeverity = this._getHighestSeverity(b.vulnerabilities);

                const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
                return severityOrder[aHighestSeverity] - severityOrder[bHighestSeverity];
            }),
            metadata: {
                scanId: options.scanId || `scan-${Date.now()}`,
                directory: scanResults.directory,
                options: { ...options }
            }
        };
    }

    /**
     * Get the highest severity from an array of vulnerabilities
     * 
     * @private
     * @param {Array} vulnerabilities - Vulnerabilities
     * @returns {string} - Highest severity
     */
    _getHighestSeverity(vulnerabilities) {
        const severityLevels = ['critical', 'high', 'medium', 'low', 'unknown'];

        for (const level of severityLevels) {
            if (vulnerabilities.some(v => v.severity?.toLowerCase() === level)) {
                return level;
            }
        }

        return 'unknown';
    }

    /**
     * Clear all cache data
     */
    async clearCache() {
        try {
            // Clear memory cache
            this.resultsCache.clear();

            // Clear file cache
            const files = await fs.readdir(this.options.cachePath);
            await Promise.all(
                files.map(file => 
                    fs.unlink(`${this.options.cachePath}/${file}`).catch(err => 
                        console.error(`Failed to delete cache file ${file}:`, err)
                    )
                )
            );
        } catch (error) {
            console.error('Error clearing cache:', error);
        }
    }
}

export default ScannerManager; 