/**
 * Package Parsers
 * 
 * Utilities for parsing package manifests across different ecosystems
 */

import fs from 'fs/promises';
import path from 'path';

/**
 * Parse an npm package.json file
 * 
 * @param {string} filePath - Path to package.json
 * @returns {Promise<Object>} - Parsed dependencies
 */
export async function parsePackageJson(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    const packageJson = JSON.parse(data);
    
    // Extract dependencies
    const dependencies = {
      ...(packageJson.dependencies || {}),
      ...(packageJson.devDependencies || {}),
    };
    
    return {
      name: packageJson.name,
      version: packageJson.version,
      ecosystem: 'npm',
      dependencies: Object.entries(dependencies).map(([name, version]) => ({
        name,
        version: version.replace(/^\^|~/, '')
      }))
    };
  } catch (error) {
    console.error(`Error parsing package.json: ${filePath}`, error);
    return null;
  }
}

/**
 * Parse a pip requirements.txt file
 * 
 * @param {string} filePath - Path to requirements.txt
 * @returns {Promise<Object>} - Parsed dependencies
 */
export async function parseRequirementsTxt(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    const lines = data.split('\n');
    
    const dependencies = [];
    
    for (const line of lines) {
      // Skip comments and empty lines
      if (line.trim().startsWith('#') || !line.trim()) continue;
      
      // Handle editable installs (e.g., -e git+...)
      if (line.trim().startsWith('-e')) continue;
      
      // Handle github/gitlab/url installs
      if (line.includes('git+') || line.includes('http://') || line.includes('https://')) continue;
      
      // Parse requirements like 'package==1.0.0', 'package>=1.0.0', etc.
      const match = line.match(/^([a-zA-Z0-9_.-]+)(?:\[.*\])?(?:[<>=!~]{1,2})(.+)$/);
      if (match) {
        dependencies.push({
          name: match[1].trim(),
          version: match[2].trim()
        });
        continue;
      }
      
      // Just package name
      const packageName = line.trim().split(' ')[0].split('#')[0].split('[')[0];
      if (packageName) {
        dependencies.push({
          name: packageName,
          version: '*'
        });
      }
    }
    
    return {
      name: path.basename(path.dirname(filePath)),
      version: '0.0.0',
      ecosystem: 'pip',
      dependencies
    };
  } catch (error) {
    console.error(`Error parsing requirements.txt: ${filePath}`, error);
    return null;
  }
}

/**
 * Parse a Go modules go.mod file
 * 
 * @param {string} filePath - Path to go.mod
 * @returns {Promise<Object>} - Parsed dependencies
 */
export async function parseGoMod(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    const lines = data.split('\n');
    
    let moduleName = '';
    const dependencies = [];
    
    for (const line of lines) {
      const trimmedLine = line.trim();
      
      // Get module name
      if (trimmedLine.startsWith('module ')) {
        moduleName = trimmedLine.substring(7).trim();
        continue;
      }
      
      // Skip lines that don't have require statements
      if (!trimmedLine.startsWith('require ') && !trimmedLine.includes(' => ')) continue;
      
      // Handle single require statements
      if (trimmedLine.startsWith('require ')) {
        const parts = trimmedLine.substring(8).trim().split(' ');
        if (parts.length >= 2) {
          dependencies.push({
            name: parts[0],
            version: parts[1].replace(/^v/, '')
          });
        }
        continue;
      }
      
      // Handle multi-line require blocks and replacements
      const match = trimmedLine.match(/^\s*([a-zA-Z0-9_.-\/]+)(?:\s+|\s+=>.*\s+)v([0-9]+\.[0-9]+\.[0-9]+.*)$/);
      if (match) {
        dependencies.push({
          name: match[1].trim(),
          version: match[2].trim()
        });
      }
    }
    
    return {
      name: moduleName,
      version: '0.0.0',
      ecosystem: 'go',
      dependencies
    };
  } catch (error) {
    console.error(`Error parsing go.mod: ${filePath}`, error);
    return null;
  }
}

/**
 * Parse a Rust Cargo.toml file
 * 
 * @param {string} filePath - Path to Cargo.toml
 * @returns {Promise<Object>} - Parsed dependencies
 */
export async function parseCargoToml(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    
    // Simple TOML parsing for dependencies section
    const dependencies = [];
    let inDependencies = false;
    
    const lines = data.split('\n');
    for (const line of lines) {
      const trimmedLine = line.trim();
      
      // Check for dependencies section
      if (trimmedLine === '[dependencies]') {
        inDependencies = true;
        continue;
      } else if (trimmedLine.startsWith('[') && trimmedLine.endsWith(']')) {
        inDependencies = false;
        continue;
      }
      
      // Process dependencies
      if (inDependencies && trimmedLine && !trimmedLine.startsWith('#')) {
        // Simple key = "value" format
        const simpleMatch = trimmedLine.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"$/);
        if (simpleMatch) {
          dependencies.push({
            name: simpleMatch[1],
            version: simpleMatch[2]
          });
          continue;
        }
        
        // Table format
        const tableMatch = trimmedLine.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{/);
        if (tableMatch) {
          // Extract version from the table
          const versionMatch = trimmedLine.match(/version\s*=\s*"([^"]+)"/);
          if (versionMatch) {
            dependencies.push({
              name: tableMatch[1],
              version: versionMatch[1]
            });
          }
        }
      }
    }
    
    // Extract package name and version
    let name = '';
    let version = '';
    
    let inPackage = false;
    for (const line of lines) {
      const trimmedLine = line.trim();
      
      if (trimmedLine === '[package]') {
        inPackage = true;
        continue;
      } else if (trimmedLine.startsWith('[') && trimmedLine.endsWith(']')) {
        inPackage = false;
        continue;
      }
      
      if (inPackage) {
        const nameMatch = trimmedLine.match(/^name\s*=\s*"([^"]+)"$/);
        if (nameMatch) {
          name = nameMatch[1];
        }
        
        const versionMatch = trimmedLine.match(/^version\s*=\s*"([^"]+)"$/);
        if (versionMatch) {
          version = versionMatch[1];
        }
      }
    }
    
    return {
      name,
      version,
      ecosystem: 'cargo',
      dependencies
    };
  } catch (error) {
    console.error(`Error parsing Cargo.toml: ${filePath}`, error);
    return null;
  }
}

/**
 * Parse a Maven pom.xml file
 * 
 * @param {string} filePath - Path to pom.xml
 * @returns {Promise<Object>} - Parsed dependencies
 */
export async function parsePomXml(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    
    // Simple regex-based XML parsing (for a production system, use a proper XML parser)
    const dependencies = [];
    
    // Extract dependencies
    const depsRegex = /<dependencies>([\s\S]*?)<\/dependencies>/g;
    const depRegex = /<dependency>([\s\S]*?)<\/dependency>/g;
    const groupIdRegex = /<groupId>(.*?)<\/groupId>/;
    const artifactIdRegex = /<artifactId>(.*?)<\/artifactId>/;
    const versionRegex = /<version>(.*?)<\/version>/;
    
    let depsMatch;
    while ((depsMatch = depsRegex.exec(data)) !== null) {
      const depsContent = depsMatch[1];
      let depMatch;
      
      while ((depMatch = depRegex.exec(depsContent)) !== null) {
        const depContent = depMatch[1];
        
        const groupIdMatch = depContent.match(groupIdRegex);
        const artifactIdMatch = depContent.match(artifactIdRegex);
        const versionMatch = depContent.match(versionRegex);
        
        if (groupIdMatch && artifactIdMatch) {
          dependencies.push({
            name: `${groupIdMatch[1]}:${artifactIdMatch[1]}`,
            version: versionMatch ? versionMatch[1] : '*'
          });
        }
      }
    }
    
    // Extract project info
    const groupId = data.match(/<groupId>(.*?)<\/groupId>/)?.[1] || '';
    const artifactId = data.match(/<artifactId>(.*?)<\/artifactId>/)?.[1] || '';
    const version = data.match(/<version>(.*?)<\/version>/)?.[1] || '0.0.0';
    
    return {
      name: artifactId ? (groupId ? `${groupId}:${artifactId}` : artifactId) : path.basename(path.dirname(filePath)),
      version,
      ecosystem: 'maven',
      dependencies
    };
  } catch (error) {
    console.error(`Error parsing pom.xml: ${filePath}`, error);
    return null;
  }
}

/**
 * Parse a .NET project file (.csproj, .fsproj, etc.)
 * 
 * @param {string} filePath - Path to project file
 * @returns {Promise<Object>} - Parsed dependencies
 */
export async function parseDotNetProject(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    
    // Simple regex-based XML parsing (for a production system, use a proper XML parser)
    const dependencies = [];
    
    // Extract package references
    const packageRefRegex = /<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"/g;
    let match;
    
    while ((match = packageRefRegex.exec(data)) !== null) {
      dependencies.push({
        name: match[1],
        version: match[2]
      });
    }
    
    // Extract project info
    const projectName = path.basename(filePath, path.extname(filePath));
    const versionMatch = data.match(/<Version>(.*?)<\/Version>/);
    const version = versionMatch ? versionMatch[1] : '0.0.0';
    
    return {
      name: projectName,
      version,
      ecosystem: 'nuget',
      dependencies
    };
  } catch (error) {
    console.error(`Error parsing .NET project file: ${filePath}`, error);
    return null;
  }
}

/**
 * Parse a PHP Composer composer.json file
 * 
 * @param {string} filePath - Path to composer.json
 * @returns {Promise<Object>} - Parsed dependencies
 */
export async function parseComposerJson(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    const composerJson = JSON.parse(data);
    
    // Extract dependencies
    const dependencies = {
      ...(composerJson.require || {}),
      ...(composerJson['require-dev'] || {})
    };
    
    // Filter out PHP version requirement
    delete dependencies.php;
    
    return {
      name: composerJson.name || path.basename(path.dirname(filePath)),
      version: composerJson.version || '0.0.0',
      ecosystem: 'composer',
      dependencies: Object.entries(dependencies).map(([name, version]) => ({
        name,
        version: version.replace(/[^0-9.]/g, '')
      }))
    };
  } catch (error) {
    console.error(`Error parsing composer.json: ${filePath}`, error);
    return null;
  }
}

/**
 * Parse a package file based on the file path
 * 
 * @param {string} filePath - Path to the package file
 * @returns {Promise<Object>} - Parsed dependencies or null if unsupported
 */
export async function parsePackageFile(filePath) {
  const fileName = path.basename(filePath).toLowerCase();
  const extension = path.extname(filePath).toLowerCase();
  
  if (fileName === 'package.json') {
    return parsePackageJson(filePath);
  } else if (fileName === 'requirements.txt') {
    return parseRequirementsTxt(filePath);
  } else if (fileName === 'go.mod') {
    return parseGoMod(filePath);
  } else if (fileName === 'cargo.toml') {
    return parseCargoToml(filePath);
  } else if (fileName === 'pom.xml') {
    return parsePomXml(filePath);
  } else if (fileName === 'composer.json') {
    return parseComposerJson(filePath);
  } else if (extension === '.csproj' || extension === '.fsproj') {
    return parseDotNetProject(filePath);
  }
  
  console.warn(`Unsupported package file format: ${filePath}`);
  return null;
}

export default {
  parsePackageJson,
  parseRequirementsTxt,
  parseGoMod,
  parseCargoToml,
  parsePomXml,
  parseDotNetProject,
  parseComposerJson,
  parsePackageFile
}; 