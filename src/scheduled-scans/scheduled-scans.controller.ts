/* eslint-disable no-useless-escape */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import { Controller, Get, Post, Delete, Body, Param, HttpException, HttpStatus, Query, Res } from '@nestjs/common';
import { ScheduledScansService } from './scheduled-scans.service';
import { Response } from 'express';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Report, ReportDocument } from './schemas/report.schema';

@Controller('schedules')
export class ScheduledScansController {
  constructor(
    private readonly scheduledScansService: ScheduledScansService,
    @InjectModel(Report.name) private reportModel: Model<ReportDocument>,
  ) {}

  @Post()
  async create(@Body() createScanDto: { url: string; frequency: 'daily' | 'weekly'; time: string; userId: string }) {
    try {
      const urlPattern = /^(https?:\/\/)?([\da-z.-]+)\.([a-z]{2,6})([/\w .-]*)*\/?$/i;
      let formattedUrl = createScanDto.url.trim();
      if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
        formattedUrl = `http://${formattedUrl}`;
      }
      if (!urlPattern.test(formattedUrl)) {
        throw new HttpException('Invalid URL', HttpStatus.BAD_REQUEST);
      }
      return await this.scheduledScansService.create({ ...createScanDto, url: formattedUrl });
    } catch (error) {
      if (error instanceof Error && error.message.includes('duplicate key')) {
        throw new HttpException(
          `A scan for URL ${createScanDto.url} at ${createScanDto.time} already exists`,
          HttpStatus.CONFLICT,
        );
      }
      throw new HttpException(error.message || 'Failed to schedule scan', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Get()
  async findAll(@Query('userId') userId: string) {
    try {
      console.log('Fetching scans for userId:', userId);
      const scans = await this.scheduledScansService.findAll(userId);
      console.log('Found scans:', scans);
      return scans;
    } catch (error) {
      throw new HttpException(error.message || 'Failed to fetch scheduled scans', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Delete(':id')
  async delete(@Param('id') id: string, @Body('userId') userId: string) {
    try {
      return await this.scheduledScansService.delete(id, userId);
    } catch (error) {
      throw new HttpException(error.message || 'Failed to cancel scan', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Get('reports')
  async findReports(@Query('userId') userId: string, @Query('limit') limit: string) {
    try {
      console.log('Fetching reports for userId:', userId, 'with limit:', limit);
      const reports = await this.scheduledScansService.findReports(userId, parseInt(limit) || 10);
      console.log('Found reports:', reports);
      return reports;
    } catch (error) {
      throw new HttpException(error.message || 'Failed to fetch reports', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Get('reports/:id/pdf')
  async downloadReportPDF(@Param('id') id: string, @Query('userId') userId: string, @Res() res: Response) {
    try {
      const report = await this.reportModel.findById(id).exec();
      if (!report || report.userId !== userId) {
        throw new HttpException('Report not found or not authorized', HttpStatus.NOT_FOUND);
      }
      const pdfDoc = this.scheduledScansService.generateReportPDF(report);
      const fileName = `${report.domain.replace(/[:\/]/g, '_')}_${new Date(report.createdAt)
        .toISOString()
        .split('T')[0]}.pdf`;

      res.set({
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="${fileName}"`,
      });

      pdfDoc.pipe(res);
      pdfDoc.end();
    } catch (error) {
      throw new HttpException(error.message || 'Failed to download report', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
