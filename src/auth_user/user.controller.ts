import { Controller,Post, Body, Put, Req, UseGuards} from '@nestjs/common';
import { UserService } from './user.service';
import {  SignupDto } from './dto/signup.dto';

import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { AuthenticationGuard } from 'src/Guards/user.guard';
import { ForgotPasswordDto } from './dto/forget-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';


@Controller('user')
export class UserController {

  constructor(private  userService: UserService) {}
  @Post('signup') //user/signup
  async signUp(@Body() signupData:SignupDto ){
    try {
      // Call the signup service method
      await this.userService.signup(signupData);

      return {
        success: true,
        message: 'User created successfully',
      };
    }catch (error) {
      console.error('Error occurred during signup:', error);
      return {
        success: false,
        message: 'An error occurred during signup',
      };
    }
  }


  @Post('login')
  async login(@Body() credentials: LoginDto) {
    return this.userService.login(credentials);
  }

  @Post('refresh')
  async refreshTokens(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.userService.refreshTokens(refreshTokenDto.refreshToken);
  }

  @UseGuards(AuthenticationGuard)
  @Put('change-password')
  async changePassword(
    @Body() changePasswordDto: ChangePasswordDto,
    @Req() req,
  ) {
    return this.userService.changePassword(
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      req.userId,
      changePasswordDto.oldPassword,
      changePasswordDto.newPassword,
    );
  }

  @Post('forget-password')
  async forgetPassword(@Body() forgetPasswordDto:ForgotPasswordDto){
    try {
    await this.userService.forgotPassword(forgetPasswordDto.email);
    return {
      success: true,
      message: 'Password reset link sent.',
    };
  } catch (error) {
    console.error('Error occurred during password reset:', error);
    return {
      success: false,
      message:'An error occurred while resetting the password.',
    };
  }
}


  @Put('reset-password')
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
  ) {
    return this.userService.resetPassword(
      resetPasswordDto.newPassword,
      resetPasswordDto.resetToken,
    );
  }

}

