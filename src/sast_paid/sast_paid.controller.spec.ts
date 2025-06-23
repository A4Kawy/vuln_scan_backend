import { Test, TestingModule } from '@nestjs/testing';
import { SastPaidController } from './sast_paid.controller';
import { SastPaidService } from './sast_paid.service';

describe('SastPaidController', () => {
  let controller: SastPaidController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [SastPaidController],
      providers: [SastPaidService],
    }).compile();

    controller = module.get<SastPaidController>(SastPaidController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
