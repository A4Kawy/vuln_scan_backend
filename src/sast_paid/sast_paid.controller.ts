/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/require-await */
import { Controller, Post, Body, BadRequestException, UseInterceptors, UploadedFile, Logger, Get, Param, Res } from '@nestjs/common';
import { SastPaidService } from './sast_paid.service';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import * as path from 'path';
import * as fs from 'fs';
import { Response } from 'express';

@Controller('sast-paid')
export class SastPaidController {
  private readonly logger = new Logger(SastPaidController.name);

  constructor(private readonly sastPaidService: SastPaidService) {}

  @Post('set-model')
  setModel(@Body('model') model: string) {
    this.logger.log(`Setting model: ${model}`);
    return this.sastPaidService.setModel(model);
  }

  @Post('set-scan-type')
  setScanType(@Body('scanType') scanType: string) {
    this.logger.log(`Setting scan type: ${scanType}`);
    return this.sastPaidService.setScanType(scanType);
  }

  @Post('set-scan-path')
  setScanPath(@Body('scanPath') scanPath: string) {
    this.logger.log(`Setting scan path: ${scanPath}`);
    return this.sastPaidService.setScanPath(scanPath);
  }

  @Post('set-output-format')
  setOutputFormat(@Body('format') format: string) {
    this.logger.log(`Setting output format: ${format}`);
    return this.sastPaidService.setOutputFormat(format);
  }

  @Post('set-email')
  setEmail(@Body('email') email: string | null) {
    this.logger.log(`Setting email: ${email || 'null'}`);
    return this.sastPaidService.setEmail(email);
  }

  @Post('run-scan')
  async runScan() {
    this.logger.log('Starting scan process');
    try {
      const result = await this.sastPaidService.runScan();
      this.logger.log('Scan completed successfully');
      return result; // Returns { content: string, fileName: string }
    } catch (error) {
      this.logger.error(`Scan failed: ${error.message}`);
      throw error;
    }
  }

  @Get('download/:filename')
  downloadFile(@Param('filename') filename: string, @Res() res: Response) {
    const filePath = path.join(__dirname, '..', '..', 'SAST', 'scan_results', filename);
    const resolvedPath = path.resolve(filePath);

    this.logger.log(`Attempting to download file: ${resolvedPath}`);

    if (!fs.existsSync(resolvedPath)) {
      this.logger.error(`File not found: ${resolvedPath}`);
      throw new BadRequestException(`File not found: ${filename}`);
    }

    this.logger.log(`Sending file: ${resolvedPath}`);
    res.download(resolvedPath, filename, (err) => {
      if (err) {
        this.logger.error(`Error sending file: ${err.message}`);
        throw new BadRequestException(`Error downloading file: ${err.message}`);
      }
    });
  }

  @Post('upload-file')
  @UseInterceptors(
    FileInterceptor('file', {
      storage: diskStorage({
        destination: (req, file, cb) => {
          const uploadDir = path.join(__dirname, '..', '..', 'SAST', 'Uploads');
          if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
          }
          cb(null, uploadDir);
        },
        filename: (req, file, cb) => {
          const timestamp = Date.now();
          const originalName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
          cb(null, `${timestamp}-${originalName}`);
        },
      }),
      fileFilter: (req, file, cb) => {
        if (!file.originalname.match(/\.(php|js|ts|py|java|cpp|c|h|go|rb)$/)) {
          return cb(new BadRequestException('Only code files are allowed!'), false);
        }
        cb(null, true);
      },
    }),
  )
  async uploadFile(@UploadedFile() file: Express.Multer.File) {
    if (!file || !file.path) {
      this.logger.error('File upload failed: No file or invalid path');
      throw new BadRequestException('File upload failed: No file or invalid path');
    }
    if (!fs.existsSync(file.path)) {
      this.logger.error(`File not found on server: ${file.path}`);
      throw new BadRequestException(`File not found on server: ${file.path}`);
    }
    this.logger.log(`File uploaded successfully: ${file.path}`);
    return { filePath: file.path };
  }
}