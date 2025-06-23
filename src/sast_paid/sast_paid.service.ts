/* eslint-disable prefer-const */
 
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

@Injectable()
export class SastPaidService {
  private readonly logger = new Logger(SastPaidService.name);
  private model: string | null = null;
  private scanType: string | null = null;
  private scanPath: string | null = null;
  private outputFormat: string | null = null;
  private email: string | null = null;
  private readonly outputDir = path.join(__dirname, '..', '..', 'SAST', 'scan_results');

  constructor() {
    this.logger.log(`Current __dirname: ${__dirname}`);
    const resolvedOutputDir = path.resolve(this.outputDir);
    this.logger.log(`Output directory: ${resolvedOutputDir}`);
    if (!fs.existsSync(resolvedOutputDir)) {
      fs.mkdirSync(resolvedOutputDir, { recursive: true });
      this.logger.log(`Created directory: ${resolvedOutputDir}`);
    }
  }

  setModel(model: string): string {
    const modelLower = model.toLowerCase().trim();
    if (modelLower !== 'bedrock' && modelLower !== 'gemini') {
      this.logger.error(`Unsupported model: ${model}`);
      throw new BadRequestException(`Unsupported model: ${model}. Use 'bedrock' or 'gemini'.`);
    }
    this.model = modelLower;
    this.logger.log(`Model set to: ${this.model}`);
    return `Model set to ${this.model}`;
  }

  setScanType(scanType: string): string {
    const scanTypeLower = scanType.toLowerCase().trim();
    const validScanTypes = ['single', 'directory', 'git'];
    if (!validScanTypes.includes(scanTypeLower)) {
      this.logger.error(`Invalid scan type: ${scanType}`);
      throw new BadRequestException(`Invalid scan type: ${scanType}. Use 'single', 'directory', or 'git'.`);
    }
    this.scanType = scanTypeLower;
    this.logger.log(`Scan type set to: ${this.scanType}`);
    return `Scan type set to ${this.scanType}`;
  }

  setScanPath(scanPath: string): { status: string; message: string } {
    const resolvedPath = path.resolve(scanPath);
    if (!scanPath || !fs.existsSync(resolvedPath)) {
      this.logger.error(`Invalid path: ${scanPath}`);
      throw new BadRequestException(`Provided path does not exist: ${scanPath}`);
    }
    this.scanPath = resolvedPath;
    this.logger.log(`Scan path set to: ${this.scanPath}`);
    return { status: 'success', message: `Scan path set to ${this.scanPath}` };
  }

  setOutputFormat(format: string): string {
    const formatLower = format.toLowerCase().trim();
    const validFormats = ['markdown', 'html', 'json'];
    if (!validFormats.includes(formatLower)) {
      this.logger.error(`Invalid output format: ${format}`);
      throw new BadRequestException(`Invalid output format: ${format}. Use 'markdown', 'html', or 'json'.`);
    }
    this.outputFormat = formatLower;
    this.logger.log(`Output format set to: ${this.outputFormat}`);
    return `Output format set to ${this.outputFormat}`;
  }

  setEmail(email: string | null): string {
    if (email === null) {
      this.email = null;
      this.logger.log('Email sending disabled');
      return 'Email sending disabled';
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      this.logger.error(`Invalid email: ${email}`);
      throw new BadRequestException(`Invalid email address: ${email}`);
    }
    this.email = email;
    this.logger.log(`Email set to: ${this.email}`);
    return `Email set to ${this.email}`;
  }

  async runScan(): Promise<{ content: string; fileName: string }> {
    const goPath = '"C:\\Program Files\\Go\\bin\\go.exe"';
    const projectPath = path.resolve(path.join(__dirname, '..', '..', 'SAST'));
    const args = ['run', 'main.go'];

    this.logger.log(`Project path: ${projectPath}`);

    if (!this.model) {
      this.logger.warn('No model set. Defaulting to "bedrock".');
      this.model = 'bedrock';
    }

    if (!this.scanType) {
      this.logger.error('No scan type set.');
      throw new BadRequestException('Scan type not set. Use set-scan-type endpoint.');
    }

    if (!this.scanPath) {
      this.logger.error('No scan path set.');
      throw new BadRequestException('Scan path not set. Use set-scan-path endpoint.');
    }

    if (!this.outputFormat) {
      this.logger.error('No output format set.');
      throw new BadRequestException('Output format not set. Use set-output-format endpoint.');
    }

    const goExePath = goPath.replace(/"/g, '');
    if (!fs.existsSync(goExePath)) {
      this.logger.error(`go.exe not found at: ${goExePath}`);
      throw new BadRequestException(`go.exe not found at: ${goExePath}`);
    }

    const modelChoice = this.model === 'gemini' ? '2' : '1';
    const scanTypeChoice = this.scanType === 'single' ? '1' : this.scanType === 'directory' ? '2' : '3';
    const outputFormatChoice = this.outputFormat === 'html' ? '2' : this.outputFormat === 'json' ? '3' : '1';
    const sendEmailChoice = this.email ? 'y' : 'n';

    this.logger.log(`Executing command: ${goPath} ${args.join(' ')} in ${projectPath}`);
    this.logger.log(`Using model: ${this.model} -> sending: ${modelChoice}`);
    this.logger.log(`Scan type: ${this.scanType} -> sending: ${scanTypeChoice}`);
    this.logger.log(`Path to scan: ${this.scanPath}`);
    this.logger.log(`Output format: ${this.outputFormat} -> sending: ${outputFormatChoice}`);
    this.logger.log(`Send email: ${sendEmailChoice}${this.email ? `, email: ${this.email}` : ''}`);

    return new Promise((resolve, reject) => {
      const child = spawn(goPath, args, { cwd: projectPath, shell: true });

      let output = '';
      let resultFileName: string | null = null;

      child.stdout.on('data', (data) => {
        const text = data.toString();
        output += text;
        this.logger.log(`Raw output: ${text}`);

        // Match any file extension
        let match = text.match(/\[INF\]\s*Results saved to: scan_results\\([^\\]+)\.(\w+)/);
        if (match && match[1] && match[2]) {
          resultFileName = `${match[1]}.${match[2]}`;
          this.logger.log(`Detected result file: ${resultFileName}`);
        }
      });

      child.stderr.on('data', (data) => {
        const text = data.toString();
        output += `Error: ${text}`;
        this.logger.error(`Error: ${text}`);
      });

      child.on('error', (err) => {
        this.logger.error(`Spawn error: ${err.message}`);
        reject(new BadRequestException(`Error: ${err.message}`));
      });

      child.on('close', (code) => {
        this.logger.log(`Process exited with code: ${code}`);
        this.logger.log(`Full stdout output: ${output}`);

        if (code !== 0 || !resultFileName) {
          this.logger.warn(`No result file detected in output: ${output}`);
          reject(new BadRequestException('No result file detected in process output'));
          return;
        }

        // Polling function to check for file existence
        const checkFile = (attempts = 5, delay = 500) => {
          const fullPath = path.join(this.outputDir, resultFileName);
          const absolutePath = path.resolve(this.outputDir, resultFileName);
          const fallbackPath = path.join(projectPath, 'scan_results', resultFileName);

          this.logger.log(`Checking file: fullPath=${fullPath}, exists=${fs.existsSync(fullPath)}`);
          this.logger.log(`Checking file: absolutePath=${absolutePath}, exists=${fs.existsSync(absolutePath)}`);
          this.logger.log(`Checking file: fallbackPath=${fallbackPath}, exists=${fs.existsSync(fallbackPath)}`);

          if (fs.existsSync(fullPath)) {
            try {
              const content = fs.readFileSync(fullPath, 'utf-8');
              this.logger.log(`Scan completed successfully, output: ${fullPath}`);
              resolve({ content, fileName: resultFileName });
            } catch (err) {
              this.logger.error(`Failed to read result file: ${err.message}`);
              reject(new BadRequestException(`Failed to read result file: ${fullPath}`));
            }
          } else if (fs.existsSync(absolutePath)) {
            try {
              const content = fs.readFileSync(absolutePath, 'utf-8');
              this.logger.log(`Scan completed successfully, output: ${absolutePath}`);
              resolve({ content, fileName: resultFileName });
            } catch (err) {
              this.logger.error(`Failed to read result file: ${err.message}`);
              reject(new BadRequestException(`Failed to read result file: ${absolutePath}`));
            }
          } else if (fs.existsSync(fallbackPath)) {
            try {
              const content = fs.readFileSync(fallbackPath, 'utf-8');
              this.logger.log(`Scan completed successfully, output: ${fallbackPath}`);
              resolve({ content, fileName: resultFileName });
            } catch (err) {
              this.logger.error(`Failed to read result file: ${err.message}`);
              reject(new BadRequestException(`Failed to read result file: ${fallbackPath}`));
            }
          } else if (attempts > 0) {
            this.logger.log(`File not found, retrying after ${delay}ms (${attempts} attempts left)`);
            setTimeout(() => checkFile(attempts - 1, delay), delay);
          } else {
            this.logger.error(`Result file not found after retries: ${fullPath}, ${absolutePath}, ${fallbackPath}`);
            reject(new BadRequestException(`Result file not found: ${fullPath}`));
          }
        };

        // Start polling
        setTimeout(() => checkFile(), 500);
      });

      setTimeout(() => {
        this.logger.log(`Sending model choice: ${modelChoice}`);
        child.stdin.write(`${modelChoice}\n`);

        setTimeout(() => {
          this.logger.log(`Sending scan type: ${scanTypeChoice}`);
          child.stdin.write(`${scanTypeChoice}\n`);

          setTimeout(() => {
            this.logger.log(`Sending path: ${this.scanPath}`);
            child.stdin.write(`${this.scanPath}\n`);

            setTimeout(() => {
              this.logger.log(`Sending output format: ${outputFormatChoice}`);
              child.stdin.write(`${outputFormatChoice}\n`);

              setTimeout(() => {
                this.logger.log(`Sending email choice: ${sendEmailChoice}`);
                child.stdin.write(`${sendEmailChoice}\n`);

                if (this.email) {
                  setTimeout(() => {
                    this.logger.log(`Sending email: ${this.email}`);
                    child.stdin.write(`${this.email}\n`);
                    child.stdin.end();
                  }, 200);
                } else {
                  child.stdin.end();
                }
              }, 200);
            }, 200);
          }, 200);
        }, 200);
      }, 200);
    });
  }
}