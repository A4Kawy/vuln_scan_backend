/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
import { Injectable, Logger } from '@nestjs/common';
import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { execSync } from 'child_process';

/**
 * Service responsible for handling URL scanning operations.
 */
@Injectable()
export class UrlService {
  private readonly logger = new Logger(UrlService.name);
  private readonly scanTimeout = 1200000; // 2 minutes timeout for regular scans
  private readonly extendedTimeout = 18000000; // 30 minutes for large domains
  private readonly largeDomains = ['notion.com', 'google.com', 'amazon.com', 'vulnweb.com', 'testfire.net'];
  private lastScanLogs = '';

  /**
   * Initiates a scan for the provided domain.
   * @param domain The domain to scan.
   * @returns A promise resolving to the scan report.
   */
  async scanUrl(domain: string): Promise<any> {
    const cleanedDomain = this.prepareDomain(domain);
    this.validateDomain(cleanedDomain);

    const { scriptPath, workingDir } = this.getScriptPaths();
    this.logger.log(`🔍 Starting scan for: ${cleanedDomain}`);
    this.logSystemResources();

    try {
      // Clean up old results directory
      const resultsDir = path.join(workingDir, 'results_all', cleanedDomain);
      if (fs.existsSync(resultsDir)) {
        fs.rmSync(resultsDir, { recursive: true, force: true });
        this.logger.log(`🧹 Cleared old results directory: ${resultsDir}`);
      }

      await this.executePythonScript(cleanedDomain, scriptPath, workingDir);
      const report = this.generateScanReport(cleanedDomain, workingDir);
      return report;
    } catch (error) {
      const details = error['details']
        ? JSON.stringify(error['details'], null, 2)
        : 'No additional details';
      this.logger.error(`💥 Critical scan failure: ${error.message}`, error.stack);
      throw new Error(`Scan failed: ${error.message} (Details: ${details})`);
    }
  }

  /**
   * Prepares the domain by cleaning and normalizing it.
   * @param rawDomain The raw domain input.
   * @returns The cleaned domain.
   */
  private prepareDomain(rawDomain: string): string {
    if (!rawDomain?.trim()) throw new Error('❌ Domain cannot be empty');
    return rawDomain
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/$/, '')
      .replace(/^www\./, '');
  }

  /**
   * Validates the domain format.
   * @param domain The domain to validate.
   */
  private validateDomain(domain: string): void {
    const regex = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/;
    if (!regex.test(domain)) throw new Error(`❌ Invalid domain format: ${domain}`);
  }

  /**
   * Retrieves paths for the Python script and working directory.
   * @returns An object containing the script path and working directory.
   */
  private getScriptPaths(): { scriptPath: string; workingDir: string } {
    const scriptPath = path.join(__dirname, '..', '..', 'Recon-test', 'master_test.py');
    if (!fs.existsSync(scriptPath)) throw new Error(`❌ Python script not found at: ${scriptPath}`);
    return {
      scriptPath,
      workingDir: path.dirname(scriptPath),
    };
  }

  /**
   * Executes the Python script for scanning.
   * @param domain The domain to scan.
   * @param scriptPath Path to the Python script.
   * @param cwd Current working directory.
   */
  private async executePythonScript(domain: string, scriptPath: string, cwd: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const pythonCmd = this.getPythonCommand();

      // Verify Python command availability
      try {
        const versionOutput = execSync(`${pythonCmd} --version`, { stdio: 'pipe' }).toString();
        this.logger.log(`🐍 Python command verified: ${pythonCmd} (${versionOutput.trim()})`);
      } catch (error) {
        const errorMsg = `Python command not found: ${pythonCmd} (${error.message})`;
        this.logger.error(errorMsg);
        return reject(new Error(errorMsg));
      }

      const isLargeDomain = this.largeDomains.includes(domain);
      const timeout = isLargeDomain ? this.extendedTimeout : this.scanTimeout;

      this.logger.log(`🚀 Executing Python script with domain: ${domain} (Timeout: ${timeout / 1000}s, Command: ${pythonCmd} ${scriptPath} ${domain})`);

      const child = spawn(`${pythonCmd} ${scriptPath} ${domain}`, {
        cwd,
        shell: true,
        timeout,
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      let errorMessages = '';
      let outputMessages = '';

      child.stdout.on('data', (data) => {
        const output = data.toString();
        outputMessages += output;
        this.lastScanLogs += output;
        this.logger.debug(`🐍 [Python Output]: ${output.trim()}`);
      });

      child.stderr.on('data', (data) => {
        const errorMsg = data.toString();
        errorMessages += errorMsg;
        this.logger.error(`🔴 [Python Error]: ${errorMsg.trim()}`);
      });

      child.on('error', (error) => {
        const errorMsg = `Failed to spawn Python process: ${error.message}`;
        this.logger.error(errorMsg);
        reject(new Error(errorMsg));
      });

      child.on('close', (code, signal) => {
        this.logger.log(`🏁 Python process closed with code: ${code}, signal: ${signal || 'none'}`);
        if (code === 0) {
          resolve();
        } else {
          const errorMsg = code === null
            ? `Python script terminated unexpectedly with no exit code (Signal: ${signal || 'unknown'})`
            : `Python script exited with code ${code}`;
          const error = new Error(errorMsg);
          error['details'] = {
            errorOutput: errorMessages || 'No error output',
            standardOutput: outputMessages.slice(-1000) || 'No standard output',
            signal: signal || 'none',
            timeout: timeout / 1000,
          };
          if (signal === 'SIGTERM') {
            error['details'].timeoutInfo = `Process likely terminated due to timeout (${timeout / 1000}s)`;
          }
          reject(error);
        }
      });
    });
  }

  /**
   * Determines the appropriate Python command based on the platform.
   * @returns The Python command to use.
   */
  private getPythonCommand(): string {
    return process.platform === 'win32' ? 'python' : 'python3';
  }

  /**
   * Groups vulnerability findings to avoid duplicate counting.
   * @param content The content to group.
   * @param type The vulnerability type.
   * @returns The grouped findings.
   */
  private groupFindings(content: string[], type: string): Array<{ url: string; parameter?: string; finding: string }> {
    this.logger.debug(`📝 [${type}] Processing ${content.length} findings`);

    const groupedFindings: Array<{ url: string; parameter?: string; finding: string }> = [];

    if (type === 'CSRF' || type === 'Sensitive Data') {
      // Special handling for CSRF and Sensitive Data
      let currentFinding: string[] = [];
      let currentUrl: string | null = null;
      let currentParameter: string | null = null;
      let isFindingBlock = false;

      for (const line of content) {
        if (line.startsWith('URL:')) {
          // Save the previous finding if it exists
          if (currentFinding.length > 0 && currentUrl) {
            groupedFindings.push({
              url: currentUrl,
              parameter: currentParameter || undefined,
              finding: currentFinding.join(' | '),
            });
            currentFinding = [];
            currentParameter = null;
          }
          currentUrl = line.match(/URL: (.*?)(?:\s|$)/)?.[1] || null;
          isFindingBlock = false;
        } else if (line.startsWith('Finding #') && currentUrl) {
          // Start a new finding under the current URL
          if (currentFinding.length > 0) {
            groupedFindings.push({
              url: currentUrl,
              parameter: currentParameter || undefined,
              finding: currentFinding.join(' | '),
            });
            currentFinding = [];
            currentParameter = null;
          }
          isFindingBlock = true;
          currentFinding.push(line);
        } else if (isFindingBlock) {
          // Add details to the current finding
          if (line.startsWith('Parameter:')) {
            currentParameter = line.match(/Parameter: (.*?)(?:\s|$)/)?.[1] || 'Unknown';
          }
          currentFinding.push(line);
        }
      }

      // Add the last finding if it exists
      if (currentFinding.length > 0 && currentUrl) {
        groupedFindings.push({
          url: currentUrl,
          parameter: currentParameter || undefined,
          finding: currentFinding.join(' | '),
        });
      }

      // Remove duplicates based on URL and finding content
      const uniqueFindings = Array.from(
        new Map(groupedFindings.map(f => [`${f.url}|${f.finding}`, f])).values()
      );

      this.logger.debug(`📝 [${type}] Grouped into ${uniqueFindings.length} findings after deduplication`);
      return uniqueFindings;
    } else {
      // Original handling for other vulnerability types
      let currentFinding: string[] = [];
      let currentUrl: string | null = null;
      let currentParameter: string | null = null;

      for (const line of content) {
        if (line.match(/^(Finding: |Vulnerable: |URL:)/)) {
          if (currentFinding.length > 0 && currentUrl) {
            groupedFindings.push({
              url: currentUrl,
              parameter: currentParameter || undefined,
              finding: currentFinding.join(' | '),
            });
            currentFinding = [];
            currentParameter = null;
          }
          if (line.startsWith('URL:')) {
            currentUrl = line.match(/URL: (.*?)(?:\s|$)/)?.[1] || null;
          } else {
            currentFinding.push(line);
          }
        } else if (line.startsWith('Parameter:')) {
          currentParameter = line.match(/Parameter: (.*?)(?:\s|$)/)?.[1] || 'Unknown';
          currentFinding.push(line);
        } else if (currentUrl) {
          currentFinding.push(line);
        }
      }

      // Add the last finding if it exists
      if (currentFinding.length > 0 && currentUrl) {
        groupedFindings.push({
          url: currentUrl,
          parameter: currentParameter || undefined,
          finding: currentFinding.join(' | '),
        });
      }

      this.logger.debug(`📝 [${type}] Grouped into ${groupedFindings.length} findings`);
      return groupedFindings;
    }
  }

  /**
   * Generates a scan report by processing scan results.
   * @param domain The scanned domain.
   * @param baseDir The base directory for result files.
   * @returns The generated scan report.
   */
  private generateScanReport(domain: string, baseDir: string): Record<string, unknown> {
    const report: any = {
      summary: {
        domain,
        total_vulnerabilities: 0,
        vulnerabilities: [],
        zero_vulnerabilities: [],
        files: {},
        timestamp: new Date().toISOString(),
        warnings: [],
        urls_with_params: 0,
        urls_without_params: 0,
      },
      reconnaissance: {
        subdomains: 0,
        unique_ips: 0,
        open_ports: [],
      },
    };

    const vulnTypes = [
      { type: 'xss', file: `${domain}_xss_results.txt`, severity: 'High', displayName: 'XSS' },
      { type: 'lfi', file: `${domain}_lfi_results.txt`, severity: 'Critical', displayName: 'LFI' },
      { type: 'cmdi', file: `${domain}_cmdi_results.txt`, severity: 'High', displayName: 'Command Injection' },
      { type: 'sqli', file: `${domain}_sqli_results.txt`, severity: 'Critical', displayName: 'SQL Injection' },
      { type: 'csrf', file: `${domain}_csrf_results.txt`, severity: 'Medium', displayName: 'CSRF' },
      { type: 'sensitive_data', file: `${domain}_sensitive_data_results.txt`, severity: 'Medium', displayName: 'Sensitive Data' },
      { type: 'prototype_pollution', file: `${domain}_prototype_pollution_results.txt`, severity: 'Low', displayName: 'Prototype Pollution' },
      { type: 'ssti', file: `${domain}_ssti_results.txt`, severity: 'Critical', displayName: 'SSTI' },
      { type: 'xxe', file: `${domain}_xxe_results.txt`, severity: 'Low', displayName: 'XXE' },
      { type: 'deserialization', file: `${domain}_deserialization_results.txt`, severity: 'High', displayName: 'Insecure Deserialization' },
      { type: 'http_smuggling', file: `${domain}_http_smuggling_results.txt`, severity: 'Medium', displayName: 'HTTP Request Smuggling' },
    ];

    const generalStats = [
      { key: 'subdomains', file: `${domain}_all_subdomains.txt` },
      { key: 'unique_ips', file: `${domain}_ips.txt` },
      { key: 'open_ports', file: `${domain}_ports.txt` },
      { key: 'urls_with_params', file: `${domain}_params.txt` },
      { key: 'urls_without_params', file: `${domain}_others.txt` },
    ];

    const searchPaths = [
      baseDir,
      path.join(baseDir, 'results_all', domain),
      path.join(baseDir, 'results_all'),
    ];

    // Check for crawling failures
    const paramsFile = path.join(baseDir, 'results_all', domain, `${domain}_params.txt`);
    const othersFile = path.join(baseDir, 'results_all', domain, `${domain}_others.txt`);
    if (fs.existsSync(paramsFile) && fs.existsSync(othersFile)) {
      const paramsContent = fs.readFileSync(paramsFile, 'utf-8').split('\n').filter(line => line.trim());
      const othersContent = fs.readFileSync(othersFile, 'utf-8').split('\n').filter(line => line.trim());
      const paramsCount = paramsContent.length;
      const othersCount = othersContent.length;
      if (paramsCount === 0 && othersCount === 0) {
        report.summary.warnings.push('⚠️ Crawling failed: No URLs found. Vulnerability scan results may be incomplete.');
      } else {
        report.summary.urls_with_params = paramsCount;
        report.summary.urls_without_params = othersCount;
      }
    } else {
      report.summary.warnings.push('⚠️ Crawling files missing: Unable to verify URLs.');
    }

    let totalVulnerabilities = 0;

    // Process vulnerability files
    for (const { type, file, severity, displayName } of vulnTypes) {
      let filePath: string | null = null;
      let content: string[] = [];

      for (const dir of searchPaths) {
        const potentialPath = path.join(dir, file);
        if (fs.existsSync(potentialPath)) {
          const stats = fs.statSync(potentialPath);
          const fileAge = Date.now() - stats.mtimeMs;
          if (fileAge > 24 * 60 * 60 * 1000) {
            this.logger.warn(`⚠️ Skipping outdated file: ${potentialPath} (Age: ${fileAge / 1000}s)`);
            continue;
          }

          if (!file.includes(domain)) {
            this.logger.warn(`⚠️ Skipping file ${potentialPath}: Does not match domain ${domain}`);
            continue;
          }

          filePath = potentialPath;
          content = fs.readFileSync(filePath, 'utf-8').split('\n').filter(line => line.trim());
          break;
        }
      }

      // Filter out irrelevant lines
      const filteredContent = content.filter(line => {
        const isExcluded = line.includes('INFO') || line.includes('DEBUG') || line.includes('Scan completed');
        return !isExcluded;
      });

      // Group findings to avoid counting duplicate lines
      const groupedFindings = this.groupFindings(filteredContent, displayName);

      this.logger.debug(`📝 [${displayName}] Raw lines: ${content.length}, Filtered lines: ${filteredContent.length}, Grouped findings: ${groupedFindings.length}`);
      if (groupedFindings.length !== filteredContent.length) {
        this.logger.debug(`📝 [${displayName}] First 3 grouped findings: ${JSON.stringify(groupedFindings.slice(0, 3))}`);
      }

      // Count unique vulnerabilities
      const vulnCount = groupedFindings.length;

      if (vulnCount > 0) {
        totalVulnerabilities += vulnCount;
        report.summary.vulnerabilities.push({
          type: displayName,
          count: vulnCount,
          severity,
          top_endpoints: groupedFindings.slice(0, 3).map(finding => {
            return finding.parameter
              ? `${finding.url} - Parameter: ${finding.parameter}`
              : `${finding.url} - Parameter: Unknown`;
          }),
        });
      } else {
        report.summary.zero_vulnerabilities.push(displayName);
      }

      // Add file path to report
      report.summary.files[displayName] = filePath
        ? filePath
        : `No vulnerabilities found for ${displayName}`;
    }

    report.summary.total_vulnerabilities = totalVulnerabilities;

    // Process reconnaissance summary
    for (const { key, file } of generalStats) {
      for (const dir of searchPaths) {
        const filePath = path.join(dir, file);
        if (fs.existsSync(filePath)) {
          const stats = fs.statSync(filePath);
          const fileAge = Date.now() - stats.mtimeMs;
          if (fileAge > 24 * 60 * 60 * 1000) {
            this.logger.warn(`⚠️ Skipping outdated file: ${filePath} (Age: ${fileAge / 1000}s)`);
            continue;
          }

          const content = fs.readFileSync(filePath, 'utf-8').split('\n').filter(line => line.trim()).map(line => line.replace(/\r$/, ''));
          if (key === 'open_ports') {
            if (content.length === 0) {
              report.summary.warnings.push(`⚠️ Port scan file is empty: ${filePath}`);
              report.reconnaissance.open_ports = [];
            } else {
              this.logger.debug(`📡 Raw port lines: ${content.slice(0, 5).join(' | ')}`);
              // Extract open ports and remove duplicates
              const uniquePorts = new Set<string>();
              const openPorts = content
                .filter(line => line.match(/^\d+\/tcp\s+open\s+\S+/))
                .map(line => {
                  const match = line.match(/^(\d+\/tcp)\s+open\s+(\S+)(?:\s+(.+))?$/);
                  if (match) {
                    const portStr = `Port ${match[1].replace('/tcp', '')}: ${match[2]}${match[3] ? ` ${match[3]}` : ''}`;
                    uniquePorts.add(portStr);
                    return portStr;
                  }
                  return null;
                })
                .filter((port): port is string => port !== null);
              report.reconnaissance.open_ports = Array.from(uniquePorts);
              this.logger.debug(`📡 Open ports extracted: ${report.reconnaissance.open_ports.length} ports`);
            }
          } else {
            report.reconnaissance[key] = content.length;
          }
          break;
        }
      }
    }

    // Add results directory path
    report.summary.results_directory = path.join(baseDir, 'results_all', domain);

    return report;
  }

  /**
   * Logs system resource usage for debugging.
   */
  private logSystemResources(): void {
    const memoryUsage = process.memoryUsage();
    this.logger.debug(`🧠 Memory Usage:
      RSS: ${Math.round(memoryUsage.rss / 1024 / 1024)}MB
      Heap: ${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB/${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB
    `);
  }
}