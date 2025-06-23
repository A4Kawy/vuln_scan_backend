/* eslint-disable @typescript-eslint/require-await */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-floating-promises */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-base-to-string */
/* eslint-disable @typescript-eslint/no-unsafe-return */
import { Injectable, Logger, ConflictException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import * as cron from 'node-cron';
import { ScheduledScan, ScheduledScanDocument } from './schemas/scheduled-scan.schema';
import { Report, ReportDocument } from './schemas/report.schema';
import * as PDFDocument from 'pdfkit';

@Injectable()
export class ScheduledScansService {
  private readonly logger = new Logger(ScheduledScansService.name);

  constructor(
    @InjectModel(ScheduledScan.name) private scheduledScanModel: Model<ScheduledScanDocument>,
    @InjectModel(Report.name) private reportModel: Model<ReportDocument>,
    private readonly httpService: HttpService,
  ) {
    this.scheduleAllScans();
  }

  async create(createScanDto: { url: string; frequency: 'daily' | 'weekly'; time: string; userId: string }) {
    const existingScan = await this.scheduledScanModel
      .findOne({
        userId: createScanDto.userId,
        url: createScanDto.url,
        time: createScanDto.time,
      })
      .exec();

    if (existingScan) {
      throw new ConflictException(
        `A scan for URL ${createScanDto.url} at ${createScanDto.time} already exists for this user.`,
      );
    }

    const scan = new this.scheduledScanModel(createScanDto);
    await scan.save();
    this.scheduleScan(scan);
    return scan;
  }

  async findAll(userId: string) {
    return this.scheduledScanModel.find({ userId }).exec();
  }

  async delete(id: string, userId: string) {
    const scan = await this.scheduledScanModel.findOneAndDelete({ _id: id, userId }).exec();
    if (!scan) {
      throw new Error('Scan not found');
    }
    return { message: 'Scan canceled' };
  }

  async findReports(userId: string, limit: number) {
    return this.reportModel
      .find({ userId })
      .sort({ createdAt: -1 })
      .limit(limit)
      .exec();
  }

  async runDASTScan(url: string, userId: string) {
    try {
      const response = await firstValueFrom(
        this.httpService.post(
          'http://127.0.0.1:3000/url/url',
          { url },
          { headers: { 'Content-Type': 'application/json' } },
        ),
      );
      const scanResult = response.data;

      if (!scanResult || typeof scanResult !== 'object') {
        throw new Error('Invalid scan result');
      }

      const report = new this.reportModel({
        userId,
        domain: typeof url === 'string' ? url : '',
        total_vulnerabilities: Number(scanResult.summary?.total_vulnerabilities) || 0,
        vulnerabilities: Array.isArray(scanResult.summary?.vulnerabilities)
          ? scanResult.summary.vulnerabilities.map((vuln: any) => ({
              type: typeof vuln.type === 'string' ? vuln.type : '',
              count: Number(vuln.count) || 0,
              severity: typeof vuln.severity === 'string' ? vuln.severity : '',
              top_endpoints: Array.isArray(vuln.top_endpoints)
                ? vuln.top_endpoints.filter((ep: any) => typeof ep === 'string')
                : [],
            }))
          : [],
        zero_vulnerabilities: Array.isArray(scanResult.summary?.zero_vulnerabilities)
          ? scanResult.summary.zero_vulnerabilities.filter((zv: any) => typeof zv === 'string')
          : [],
        urls_with_params: Number(scanResult.summary?.urls_with_params) || 0,
        urls_without_params: Number(scanResult.summary?.urls_without_params) || 0,
      });
      await report.save();

      return scanResult;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error(`Failed to run DAST scan for ${url}: ${message}`);
      throw error;
    }
  }

  async generateReportHtml(report: ReportDocument) {
    const severityColor = (severity: string) => {
      switch (severity) {
        case 'Critical': return 'bg-red-500';
        case 'High': return 'bg-orange-500';
        case 'Medium': return 'bg-yellow-500';
        default: return 'bg-gray-500';
      }
    };

    return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Scan Report - ${report.domain}</title>
        <script src="https://cdn.tailwindcss.com"></script>
      </head>
      <body class="bg-gray-900 text-white font-sans min-h-screen p-6">
        <div class="container mx-auto max-w-5xl">
          <h1 class="text-3xl font-bold text-blue-400 mb-6">Security Scan Report</h1>
          
          <div class="bg-gray-800 rounded-lg p-6 mb-6 shadow-lg">
            <h2 class="text-xl font-semibold text-blue-300 mb-4">Report Summary</h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 text-gray-300">
              <div>
                <p><strong>Domain:</strong> ${report.domain}</p>
                <p><strong>Total Vulnerabilities:</strong> ${report.total_vulnerabilities}</p>
                <p><strong>URLs with Parameters:</strong> ${report.urls_with_params}</p>
              </div>
              <div>
                <p><strong>Scan Date:</strong> ${new Date(report.createdAt).toLocaleString('en-US')}</p>
                <p><strong>URLs without Parameters:</strong> ${report.urls_without_params}</p>
              </div>
            </div>
          </div>

          <div class="bg-gray-800 rounded-lg p-6 mb-6 shadow-lg">
            <h2 class="text-xl font-semibold text-blue-300 mb-4">Detected Vulnerabilities</h2>
            <div class="overflow-x-auto">
              <table class="min-w-full divide-y divide-gray-700">
                <thead class="bg-gray-900">
                  <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-blue-300 uppercase tracking-wider">Vulnerability Type</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-blue-300 uppercase tracking-wider">Count</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-blue-300 uppercase tracking-wider">Severity</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-blue-300 uppercase tracking-wider">Top Affected Endpoints</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-700">
                  ${report.vulnerabilities
                    .map(
                      (vuln) => `
                    <tr class="hover:bg-gray-700">
                      <td class="px-6 py-4 whitespace-nowrap text-sm text-white">${vuln.type}</td>
                      <td class="px-6 py-4 whitespace-nowrap text-sm text-white">${vuln.count}</td>
                      <td class="px-6 py-4 whitespace-nowrap text-sm">
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${severityColor(
                          vuln.severity,
                        )} text-white">
                          ${vuln.severity === 'Critical' ? '⚠️ ' : ''}${vuln.severity}
                        </span>
                      </td>
                      <td class="px-6 py-4 text-sm text-gray-300">
                        <ul class="list-disc list-inside">
                          ${vuln.top_endpoints.map((endpoint) => `<li class="truncate max-w-md">${endpoint}</li>`).join('')}
                        </ul>
                      </td>
                    </tr>
                  `,
                    )
                    .join('')}
                </tbody>
              </table>
            </div>
          </div>

          ${
            report.zero_vulnerabilities.length > 0
              ? `
          <div class="bg-gray-800 rounded-lg p-6 shadow-lg">
            <h2 class="text-xl font-semibold text-green-400 mb-4">Non-Detected Vulnerabilities</h2>
            <div class="flex flex-wrap gap-2">
              ${report.zero_vulnerabilities
                .map(
                  (zeroVuln) => `
                <span class="inline-flex items-center px-3 py-1 rounded-full text-sm bg-green-500/20 text-green-400">
                  ✅ ${zeroVuln}
                </span>
              `,
                )
                .join('')}
            </div>
          </div>
          `
              : ''
          }
        </div>
      </body>
      </html>
    `;
  }

  generateReportPDF(report: ReportDocument): PDFDocument {
    const doc = new PDFDocument({ size: 'A4', margin: 30 });

    doc.font('Helvetica');

    doc.fontSize(24).fillColor('blue').text(`Security Scan Report - ${report.domain}`, { align: 'center' });
    doc.moveDown();

    doc.fontSize(16).fillColor('black').text('Report Summary', { underline: true });
    doc.fontSize(12).fillColor('black');
    doc.text(`Domain: ${report.domain}`);
    doc.text(`Total Vulnerabilities: ${report.total_vulnerabilities}`);
    doc.text(`Scan Date: ${new Date(report.createdAt).toLocaleString('en-US')}`);
    doc.text(`URLs with Parameters: ${report.urls_with_params}`);
    doc.text(`URLs without Parameters: ${report.urls_without_params}`);
    doc.moveDown();

    doc.fontSize(16).fillColor('black').text('Detected Vulnerabilities', { underline: true });
    doc.fontSize(10);
    doc.moveDown(0.5);

    const tableTop = doc.y;
    const colWidths = [150, 50, 80, 230];
    const colPositions = [50, 200, 250, 330];
    colWidths.forEach((width, i) => {
      doc.rect(colPositions[i], tableTop, width, 20).fill('lightgray');
    });
    doc.fillColor('white');
    doc.text('Vulnerability Type', colPositions[0] + 5, tableTop + 5);
    doc.text('Count', colPositions[1] + 5, tableTop + 5);
    doc.text('Severity', colPositions[2] + 5, tableTop + 5);
    doc.text('Top Affected Endpoints', colPositions[3] + 5, tableTop + 5);

    let yPos = tableTop + 20;
    report.vulnerabilities.forEach((vuln) => {
      colWidths.forEach((width, i) => {
        doc.rect(colPositions[i], yPos, width, 30).stroke();
      });
      doc.fillColor('black');
      doc.text(vuln.type, colPositions[0] + 5, yPos + 5);
      doc.text(vuln.count.toString(), colPositions[1] + 5, yPos + 5);
      doc.text(vuln.severity, colPositions[2] + 5, yPos + 5);
      doc.text(vuln.top_endpoints.join('\n'), colPositions[3] + 5, yPos + 5, { width: 220 });
      yPos += 30;
    });

    doc.moveDown();

    if (report.zero_vulnerabilities.length > 0) {
      doc.fontSize(16).fillColor('black').text('Non-Detected Vulnerabilities', { underline: true });
      doc.fontSize(12).fillColor('green');
      report.zero_vulnerabilities.forEach((vuln) => {
        doc.text(`- ${vuln}`);
      });
      doc.moveDown();
    }

    return doc;
  }

  private scheduleScan(scan: ScheduledScanDocument) {
    const [hours, minutes] = scan.time.split(':').map(Number);
    const cronExpression =
      scan.frequency === 'daily'
        ? `${minutes} ${hours} * * *`
        : `${minutes} ${hours} * * 0`;

    const jobName = String(scan._id);
    this.logger.log(`Scheduling scan ${jobName} for ${scan.url} at ${scan.time} (${scan.frequency})`);

    cron.schedule(cronExpression, async () => {
      try {
        const result = await this.runDASTScan(scan.url, scan.userId);
        this.logger.log(`Scan completed for ${scan.url}: ${JSON.stringify(result)}`);
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        this.logger.error(`Failed to scan ${scan.url}: ${message}`);
      }
    });
  }

  private async scheduleAllScans() {
    const scans = await this.scheduledScanModel.find().exec();
    scans.forEach((scan) => this.scheduleScan(scan));
  }
}