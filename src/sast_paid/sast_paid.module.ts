import { Module } from '@nestjs/common';
import { SastPaidService } from './sast_paid.service';
import { SastPaidController } from './sast_paid.controller';
import { MulterModule } from '@nestjs/platform-express';

@Module({
  imports: [
    MulterModule.register({
      dest: './SAST/uploads',
    }),
  ],
  providers: [SastPaidService],
  controllers: [SastPaidController],
})
export class SastPaidModule {}