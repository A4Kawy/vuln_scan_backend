import { Controller, Post, Body } from '@nestjs/common';
import { UrlService } from './url.service';
import { UrlDto } from './dto/url.dto';

@Controller('url')
export class UrlController {
  constructor(private readonly urlService: UrlService) {}

  @Post('url')
  async scan(@Body() dto: UrlDto) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return await this.urlService.scanUrl(dto.url);
  }
}


