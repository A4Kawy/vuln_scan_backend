import { Module } from '@nestjs/common';
import { SastService } from './sast.service';
import { SastController } from './sast.controller';

@Module({
  controllers: [SastController],
  providers: [SastService],
})
export class SastModule {}
