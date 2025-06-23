import { Test, TestingModule } from '@nestjs/testing';
import { SastService } from './sast.service';

describe('SastService', () => {
  let service: SastService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [SastService],
    }).compile();

    service = module.get<SastService>(SastService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
