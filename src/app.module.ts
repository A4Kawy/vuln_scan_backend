import { Module } from '@nestjs/common';

import { MongooseModule } from '@nestjs/mongoose';
import { UserModule } from './auth_user/user.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
// import { VulnScanModule } from './vuln_scan/vuln_scan.module';
import { UrlModule } from './url/url.module';
// import { ReconModule } from './recon/recon.module';
import { SastModule } from './sast/sast.module';
import { SastPaidModule } from './sast_paid/sast_paid.module';
import { ChatModule } from './chat/chat.module';
import { ScheduledScansModule } from './scheduled-scans/scheduled-scans.module';
import config from './config';

@Module({
   
  imports: [ConfigModule.forRoot({
    isGlobal: true,
    cache: true,
    load: [config],
  }),
  JwtModule.registerAsync({
    imports: [ConfigModule],
    // eslint-disable-next-line @typescript-eslint/require-await
    useFactory: async (config) => ({
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
      secret: config.get('jwt.secret'),
    }),
    global: true,
    inject: [ConfigService],
  }),
  MongooseModule.forRootAsync({
    imports: [ConfigModule],
    // eslint-disable-next-line @typescript-eslint/require-await
    useFactory: async (config) => ({
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
      uri: config.get('database.connectionString'),
    }),
    inject: [ConfigService],
  }), UserModule, UrlModule, SastModule, SastPaidModule, ChatModule, ScheduledScansModule],
  controllers: [],
  providers: [],
})
export class AppModule {}

