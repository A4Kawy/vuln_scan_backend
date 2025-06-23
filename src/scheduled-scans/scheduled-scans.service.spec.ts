import { Test, TestingModule } from '@nestjs/testing';
import { ScheduledScansService } from './scheduled-scans.service';

describe('ScheduledScansService', () => {
  let service: ScheduledScansService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ScheduledScansService],
    }).compile();

    service = module.get<ScheduledScansService>(ScheduledScansService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
