import { Test, TestingModule } from '@nestjs/testing';
import { SastPaidService } from './sast_paid.service';

describe('SastPaidService', () => {
  let service: SastPaidService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [SastPaidService],
    }).compile();

    service = module.get<SastPaidService>(SastPaidService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
