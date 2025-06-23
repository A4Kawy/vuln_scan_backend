import { Test, TestingModule } from '@nestjs/testing';
import { ScheduledScansController } from './scheduled-scans.controller';
import { ScheduledScansService } from './scheduled-scans.service';

describe('ScheduledScansController', () => {
  let controller: ScheduledScansController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ScheduledScansController],
      providers: [ScheduledScansService],
    }).compile();

    controller = module.get<ScheduledScansController>(ScheduledScansController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
