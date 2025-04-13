/**
 * Version Parsers
 * 
 * Utilities for parsing and comparing version numbers across different ecosystems
 */

import semver from 'semver';

/**
 * Parse a version string based on the ecosystem
 * 
 * @param {string} version - Version string to parse
 * @param {string} ecosystem - Package ecosystem (npm, pip, etc.)
 * @returns {string|null} - Normalized version string or null if invalid
 */
export function parseVersion(version, ecosystem) {
  if (!version) return null;
  
  switch (ecosystem) {
    case 'npm':
      // npm uses semver
      try {
        const parsed = semver.valid(semver.coerce(version));
        return parsed || version;
      } catch (error) {
        return version;
      }
      
    case 'pip':
      // Python PEP 440 version parsing
      // This is a simplified implementation
      return parsePythonVersion(version);
      
    case 'go':
      // Go module versions generally follow semver with v prefix
      try {
        if (version.startsWith('v')) {
          const parsed = semver.valid(semver.coerce(version.substring(1)));
          return parsed ? `v${parsed}` : version;
        } else {
          const parsed = semver.valid(semver.coerce(version));
          return parsed || version;
        }
      } catch (error) {
        return version;
      }
      
    case 'cargo':
      // Rust/Cargo uses semver
      try {
        const parsed = semver.valid(semver.coerce(version));
        return parsed || version;
      } catch (error) {
        return version;
      }
      
    case 'maven':
      // Maven has its own versioning scheme
      return parseMavenVersion(version);
      
    case 'composer':
      // Composer uses semver
      try {
        const parsed = semver.valid(semver.coerce(version));
        return parsed || version;
      } catch (error) {
        return version;
      }
      
    case 'nuget':
      // NuGet uses semver 2.0
      try {
        const parsed = semver.valid(semver.coerce(version));
        return parsed || version;
      } catch (error) {
        return version;
      }
      
    default:
      // Default to semver for unknown ecosystems
      try {
        const parsed = semver.valid(semver.coerce(version));
        return parsed || version;
      } catch (error) {
        return version;
      }
  }
}

/**
 * Compare version strings based on ecosystem
 * 
 * @param {string} version - Version to check
 * @param {string} range - Version range or constraint
 * @param {string} ecosystem - Package ecosystem (npm, pip, etc)
 * @returns {boolean} - Whether version satisfies the range
 */
export function compareVersions(version, range, ecosystem) {
  if (!version || !range) return false;
  
  switch (ecosystem) {
    case 'npm':
      // npm uses semver
      try {
        return semver.satisfies(semver.coerce(version), range, { includePrerelease: true });
      } catch (error) {
        console.warn(`Error comparing npm versions: ${version} against ${range}`, error);
        return false;
      }
      
    case 'pip':
      // Python PEP 440 version comparison
      return comparePythonVersions(version, range);
      
    case 'go':
      // Go module versions
      try {
        // Handle v-prefixed versions
        let versionStr = version;
        let rangeStr = range;
        
        if (versionStr.startsWith('v')) {
          versionStr = versionStr.substring(1);
        }
        
        // Replace v-prefix in range expressions
        rangeStr = rangeStr.replace(/v(?=\d)/g, '');
        
        return semver.satisfies(semver.coerce(versionStr), rangeStr, { includePrerelease: true });
      } catch (error) {
        console.warn(`Error comparing go versions: ${version} against ${range}`, error);
        return false;
      }
      
    case 'cargo':
      // Rust/Cargo uses semver
      try {
        return semver.satisfies(semver.coerce(version), range, { includePrerelease: true });
      } catch (error) {
        console.warn(`Error comparing cargo versions: ${version} against ${range}`, error);
        return false;
      }
      
    case 'maven':
      // Maven has its own versioning scheme
      return compareMavenVersions(version, range);
      
    case 'composer':
      // Composer uses semver
      try {
        return semver.satisfies(semver.coerce(version), range, { includePrerelease: true });
      } catch (error) {
        console.warn(`Error comparing composer versions: ${version} against ${range}`, error);
        return false;
      }
      
    case 'nuget':
      // NuGet uses semver 2.0
      try {
        return semver.satisfies(semver.coerce(version), range, { includePrerelease: true });
      } catch (error) {
        console.warn(`Error comparing nuget versions: ${version} against ${range}`, error);
        return false;
      }
      
    default:
      // Default to semver for unknown ecosystems
      try {
        return semver.satisfies(semver.coerce(version), range, { includePrerelease: true });
      } catch (error) {
        console.warn(`Error comparing versions: ${version} against ${range}`, error);
        return false;
      }
  }
}

/**
 * Parse a Python version (PEP 440)
 * 
 * @param {string} version - Python version string
 * @returns {string} - Normalized version string
 */
function parsePythonVersion(version) {
  // Simplified PEP 440 handling
  // Remove leading/trailing whitespace and 'v' prefix
  let normalized = version.trim().replace(/^[vV]/, '');
  
  // Handle epoch
  const epochMatch = normalized.match(/^(\d+)!/);
  const epoch = epochMatch ? parseInt(epochMatch[1], 10) : 0;
  
  if (epochMatch) {
    normalized = normalized.substring(epochMatch[0].length);
  }
  
  // Extract release segment
  const releaseMatch = normalized.match(/^(\d+(?:\.\d+)*)/);
  let release = releaseMatch ? releaseMatch[1] : '0.0.0';
  
  // Ensure at least three components (major.minor.patch)
  const releaseParts = release.split('.');
  while (releaseParts.length < 3) {
    releaseParts.push('0');
  }
  release = releaseParts.slice(0, 3).join('.');
  
  // Simplified handling of pre-release, post-release and dev releases
  let prerelease = '';
  if (normalized.includes('a') || normalized.includes('alpha')) {
    prerelease = '-alpha';
  } else if (normalized.includes('b') || normalized.includes('beta')) {
    prerelease = '-beta';
  } else if (normalized.includes('rc')) {
    prerelease = '-rc';
  }
  
  return `${release}${prerelease}`;
}

/**
 * Compare Python versions
 * 
 * @param {string} version - Version to check
 * @param {string} range - Version range or constraint
 * @returns {boolean} - Whether version satisfies the range
 */
function comparePythonVersions(version, range) {
  try {
    // Simplified parsing for Python version ranges
    // Convert to semver-like for comparison
    
    const normalizedVersion = parsePythonVersion(version);
    
    // Handle common operators
    if (range.includes('||')) {
      // OR condition
      const ranges = range.split('||').map(r => r.trim());
      return ranges.some(r => comparePythonVersions(version, r));
    }
    
    if (range.startsWith('==')) {
      // Exact match
      const rangeVersion = parsePythonVersion(range.substring(2).trim());
      return normalizedVersion === rangeVersion;
    }
    
    if (range.startsWith('!=')) {
      // Not equal
      const rangeVersion = parsePythonVersion(range.substring(2).trim());
      return normalizedVersion !== rangeVersion;
    }
    
    if (range.startsWith('<=')) {
      // Less than or equal
      const rangeVersion = parsePythonVersion(range.substring(2).trim());
      return semver.lte(normalizedVersion, rangeVersion);
    }
    
    if (range.startsWith('<')) {
      // Less than
      const rangeVersion = parsePythonVersion(range.substring(1).trim());
      return semver.lt(normalizedVersion, rangeVersion);
    }
    
    if (range.startsWith('>=')) {
      // Greater than or equal
      const rangeVersion = parsePythonVersion(range.substring(2).trim());
      return semver.gte(normalizedVersion, rangeVersion);
    }
    
    if (range.startsWith('>')) {
      // Greater than
      const rangeVersion = parsePythonVersion(range.substring(1).trim());
      return semver.gt(normalizedVersion, rangeVersion);
    }
    
    if (range.includes(',')) {
      // Range like ">= 1.0.0, < 2.0.0"
      const conditions = range.split(',').map(r => r.trim());
      return conditions.every(condition => comparePythonVersions(version, condition));
    }
    
    // Try direct semver comparison as fallback
    return semver.satisfies(normalizedVersion, range, { includePrerelease: true });
  } catch (error) {
    console.warn(`Error comparing Python versions: ${version} against ${range}`, error);
    return false;
  }
}

/**
 * Parse a Maven version
 * 
 * @param {string} version - Maven version string
 * @returns {string} - Normalized version string
 */
function parseMavenVersion(version) {
  // Simplified Maven version parsing
  // Remove leading/trailing whitespace
  let normalized = version.trim();
  
  // Extract the numeric part for semver compatibility
  const releaseMatch = normalized.match(/^(\d+(?:\.\d+)*)/);
  let release = releaseMatch ? releaseMatch[1] : '0.0.0';
  
  // Ensure at least three components (major.minor.patch)
  const releaseParts = release.split('.');
  while (releaseParts.length < 3) {
    releaseParts.push('0');
  }
  release = releaseParts.slice(0, 3).join('.');
  
  // Simplified qualifier handling
  let qualifier = '';
  if (normalized.includes('-SNAPSHOT')) {
    qualifier = '-SNAPSHOT';
  } else if (normalized.includes('-alpha')) {
    qualifier = '-alpha';
  } else if (normalized.includes('-beta')) {
    qualifier = '-beta';
  } else if (normalized.includes('-RC') || normalized.includes('-rc')) {
    qualifier = '-rc';
  }
  
  return `${release}${qualifier}`;
}

/**
 * Compare Maven versions
 * 
 * @param {string} version - Version to check
 * @param {string} range - Version range or constraint
 * @returns {boolean} - Whether version satisfies the range
 */
function compareMavenVersions(version, range) {
  try {
    // Simplified Maven version range parsing
    const normalizedVersion = parseMavenVersion(version);
    
    // Handle Maven version ranges
    if (range.startsWith('[') && range.endsWith(']')) {
      // Inclusive range [1.0.0,2.0.0]
      const [min, max] = range.substring(1, range.length - 1).split(',').map(v => parseMavenVersion(v));
      return semver.gte(normalizedVersion, min) && semver.lte(normalizedVersion, max);
    }
    
    if (range.startsWith('(') && range.endsWith(']')) {
      // Range like (1.0.0,2.0.0]
      const [min, max] = range.substring(1, range.length - 1).split(',').map(v => parseMavenVersion(v));
      return semver.gt(normalizedVersion, min) && semver.lte(normalizedVersion, max);
    }
    
    if (range.startsWith('[') && range.endsWith(')')) {
      // Range like [1.0.0,2.0.0)
      const [min, max] = range.substring(1, range.length - 1).split(',').map(v => parseMavenVersion(v));
      return semver.gte(normalizedVersion, min) && semver.lt(normalizedVersion, max);
    }
    
    if (range.startsWith('(') && range.endsWith(')')) {
      // Exclusive range (1.0.0,2.0.0)
      const [min, max] = range.substring(1, range.length - 1).split(',').map(v => parseMavenVersion(v));
      return semver.gt(normalizedVersion, min) && semver.lt(normalizedVersion, max);
    }
    
    // Handle simple version specs
    if (range.startsWith('=')) {
      // Exact match
      const rangeVersion = parseMavenVersion(range.substring(1).trim());
      return normalizedVersion === rangeVersion;
    }
    
    // Try direct semver comparison as fallback
    return semver.satisfies(normalizedVersion, range, { includePrerelease: true });
  } catch (error) {
    console.warn(`Error comparing Maven versions: ${version} against ${range}`, error);
    return false;
  }
}

// Export functions
export default {
  parseVersion,
  compareVersions
}; 