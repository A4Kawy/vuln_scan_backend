import { Controller, Get, Post, Body, Param, StreamableFile, BadRequestException, UseInterceptors, UploadedFile } from '@nestjs/common';
import { SastService } from './sast.service';
import { FileInterceptor } from '@nestjs/platform-express';

interface ModelDto {
  model: string;
}

interface FilePathDto {
  filePath: string;
}

interface ScanData {
  scanType?: string;
}

@Controller('sast')
export class SastController {
  constructor(private readonly sastService: SastService) {}

  @Get('status')
  getStatus(): string {
    return this.sastService.getStatus();
  }

  @Post('set-model')
  setModel(@Body() modelDto: ModelDto): string {
    return this.sastService.setModel(modelDto.model);
  }

  @Post('upload-file')
  @UseInterceptors(FileInterceptor('file'))
  async uploadFile(@UploadedFile() file: Express.Multer.File) {
    if (!file) {
      throw new BadRequestException('No file provided');
    }
    return this.sastService.uploadFile(file);
  }

  @Post('set-file-path')
  setFilePath(@Body() filePathDto: FilePathDto): string {
    return this.sastService.setFilePath(filePathDto.filePath);
  }

  @Post('run')
  async runScan(@Body() scanData: ScanData): Promise<{ message: string; fileName: string }> {
    return this.sastService.runScan(scanData);
  }

  @Get('download/:fileName')
  downloadFile(@Param('fileName') fileName: string): StreamableFile {
    return this.sastService.getScanOutputFile(fileName);
  }

  @Get('download-text/:fileName')
  getScanOutputText(@Param('fileName') fileName: string): string {
    return this.sastService.getScanOutputText(fileName);
  }
}