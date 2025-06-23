import { Test, TestingModule } from '@nestjs/testing';
import { SastController } from './sast.controller';
import { SastService } from './sast.service';

describe('SastController', () => {
  let controller: SastController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [SastController],
      providers: [SastService],
    }).compile();

    controller = module.get<SastController>(SastController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
