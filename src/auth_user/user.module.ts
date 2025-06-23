import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './schemas/user.schema';
import { RefreshToken, RefreshTokenSchema } from './schemas/refresh-token.schema';
import { ResetToken, ResetTokenSchema } from './schemas/reset-token.schema';
import { MailService } from 'src/services/services/mail.service';


@Module({
  imports: [MongooseModule.forFeature([
    { name: User.name, schema: UserSchema },
    {name:RefreshToken.name,schema:RefreshTokenSchema},
    {name:ResetToken.name,schema:ResetTokenSchema}
  ]),
],
  controllers: [UserController],
  providers: [UserService,MailService],
})
export class UserModule {}
