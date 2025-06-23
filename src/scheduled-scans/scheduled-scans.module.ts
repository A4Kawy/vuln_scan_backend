 
import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ScheduleModule } from '@nestjs/schedule';
import { HttpModule } from '@nestjs/axios';
import { ScheduledScansService } from './scheduled-scans.service';
import { ScheduledScansController } from './scheduled-scans.controller';
import { ScheduledScan, ScheduledScanSchema } from './schemas/scheduled-scan.schema';
import { ReportSchema } from './schemas/report.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: ScheduledScan.name, schema: ScheduledScanSchema },
      { name: 'Report', schema: ReportSchema },
    ]),
    ScheduleModule.forRoot(),
    HttpModule,
  ],
  controllers: [ScheduledScansController],
  providers: [ScheduledScansService],
})
export class ScheduledScansModule {}