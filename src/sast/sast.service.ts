/* eslint-disable @typescript-eslint/require-await */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { StreamableFile } from '@nestjs/common';
import { Express } from 'express';

interface ScanData {
  scanType?: string;
}

@Injectable()
export class SastService {
  private readonly logger = new Logger(SastService.name);
  private readonly outputDir = path.join(__dirname, '..', '..', 'SAST', 'scan_results');
  private readonly tempDir = path.join(os.tmpdir(), 'sast-temp');
  private model: string | null = null;
  private filePath: string | null = null;
  private originalFileName: string | null = null;

  constructor() {
    [this.outputDir, this.tempDir].forEach((dir) => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        this.logger.log(`Created directory: ${dir}`);
      }
    });
    this.cleanupOldFiles(this.tempDir);
    this.cleanupOldFiles(this.outputDir);
  }

  private cleanupOldFiles(dir: string, maxAge: number = 24 * 60 * 60 * 1000) {
    try {
      fs.readdirSync(dir).forEach((file) => {
        const filePath = path.join(dir, file);
        const stats = fs.statSync(filePath);
        if (Date.now() > stats.mtime.getTime() + maxAge) {
          fs.unlinkSync(filePath);
          this.logger.log(`Deleted old file: ${filePath}`);
        }
      });
    } catch (error) {
      this.logger.error(`Error cleaning up old files in ${dir}: ${error.message}`);
    }
  }

  async uploadFile(file: Express.Multer.File): Promise<{ filePath: string }> {
    if (!file) {
      this.logger.error('No file uploaded');
      throw new BadRequestException('No file uploaded');
    }
    const sanitizedFileName = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    const filePath = path.join(this.tempDir, sanitizedFileName);
    try {
      fs.writeFileSync(filePath, file.buffer);
      if (!fs.existsSync(filePath)) {
        this.logger.error(`Failed to save file: ${filePath}`);
        throw new BadRequestException(`Failed to save file: ${filePath}`);
      }
      this.originalFileName = sanitizedFileName;
      this.logger.log(`File uploaded to: ${filePath}`);
      return { filePath };
    } catch (error) {
      this.logger.error(`Error saving file: ${error.message}`);
      throw new BadRequestException(`Error saving file: ${error.message}`);
    }
  }

  getStatus(): string {
    return 'SAST service is running';
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

  setFilePath(filePath: string): string {
    const absolutePath = path.resolve(filePath.trim());
    if (!fs.existsSync(absolutePath)) {
      this.logger.error(`Path does not exist: ${absolutePath}`);
      throw new BadRequestException(`Provided path does not exist: ${absolutePath}`);
    }
    this.filePath = absolutePath;
    this.logger.log(`File path set to: ${this.filePath}`);
    return `File path set to ${absolutePath}`;
  }

  async runScan(data: ScanData = {}): Promise<{ message: string; fileName: string }> {
    const goPath = '"C:\\Program Files\\Go\\bin\\go.exe"';
    const projectPath = path.join(__dirname, '..', '..', 'SAST');
    const args = ['run', 'main.go'];

    const modelChoice = this.model === 'gemini' ? '2' : '1';
    if (!this.model) {
      this.logger.warn('No model set. Defaulting to "bedrock".');
      this.model = 'bedrock';
    }

    if (!this.filePath) {
      this.logger.error('No file path set.');
      throw new BadRequestException('File path must be set before running scan.');
    }

    if (!fs.existsSync(goPath.replace(/"/g, ''))) {
      this.logger.error(`go.exe not found at: ${goPath}`);
      throw new BadRequestException(`go.exe not found at: ${goPath}`);
    }

    this.logger.log(`Executing command: ${goPath} ${args.join(' ')} in ${projectPath}`);
    this.logger.log(`Using model: ${this.model} -> sending: ${modelChoice}`);
    this.logger.log(`Resolved path to scan: ${this.filePath}`);

    return new Promise((resolve, reject) => {
      const child = spawn(goPath, args, { cwd: projectPath, shell: true });

      let output = '';
      let resultFileName: string | null = null;

      child.stdout.on('data', (data) => {
        const text = data.toString();
        output += text;
        this.logger.log(`Output: ${text}`);

        // استخراج اسم ملف النتائج مع التأكد من أن الامتداد .md فقط
        const match = text.match(/Results saved to: scan_results\\([^\\]+)\.md/);
        if (match && match[1]) {
          resultFileName = `${match[1]}.md.md`; // إضافة .md.md لضمان التنسيق medium.php_YYYYMMDD_HHMMSS.md.md
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
        if (code === 0 && resultFileName) {
          const fullPath = path.join(this.outputDir, resultFileName);
          if (fs.existsSync(fullPath)) {
            this.logger.log(`Scan completed successfully, output: ${fullPath}`);
            resolve({
              message: 'scan completed',
              fileName: resultFileName,
            });
          } else {
            this.logger.error(`Result file not found: ${fullPath}`);
            reject(new BadRequestException(`Result file not found: ${fullPath}`));
          }
        } else {
          this.logger.error(`Process exited with code ${code} or no result file detected`);
          reject(new BadRequestException(`Process exited with code ${code} or no result file detected`));
        }
      });

      setTimeout(() => {
        this.logger.log(`Sending model choice: ${modelChoice}`);
        child.stdin.write(`${modelChoice}\n`);

        if (modelChoice === '2') {
          setTimeout(() => {
            this.logger.log(`Gemini - sending file path: ${this.filePath}`);
            child.stdin.write(`${this.filePath}\n`);
            setTimeout(() => {
              child.stdin.write('1\n');
              child.stdin.end();
            }, 200);
          }, 200);
        } else {
          setTimeout(() => {
            child.stdin.write('1\n');
            setTimeout(() => {
              this.logger.log(`Bedrock - sending path: ${this.filePath}`);
              child.stdin.write(`${this.filePath}\n`);
              setTimeout(() => {
                child.stdin.write('1\n');
                child.stdin.end();
              }, 200);
            }, 200);
          }, 200);
        }
      }, 200);
    });
  }

  getScanOutputFile(fileName: string): StreamableFile {
    this.logger.log(`Attempting to download file: ${fileName}`);
    const filePath = path.join(this.outputDir, fileName);
    this.logger.log(`Checking file at: ${filePath}`);
    if (!fs.existsSync(filePath)) {
      this.logger.error(`File not found: ${filePath}`);
      throw new BadRequestException(`File not found: ${filePath}`);
    }
    const file = fs.createReadStream(filePath);
    this.logger.log(`Serving file: ${filePath}`);
    return new StreamableFile(file);
  }

  getScanOutputText(fileName: string): string {
    this.logger.log(`Attempting to retrieve text of file: ${fileName}`);
    const filePath = path.join(this.outputDir, fileName);
    this.logger.log(`Checking file at: ${filePath}`);
    if (!fs.existsSync(filePath)) {
      this.logger.error(`File not found: ${filePath}`);
      throw new BadRequestException(`File not found: ${fileName}`);
    }
    const content = fs.readFileSync(filePath, 'utf8');
    this.logger.log(`Read file content: ${filePath}`);
    return content;
  }
}