//  eslint-disable @typescript-eslint/no-unsafe-member-access 
import { BadRequestException, Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { SignupDto } from './dto/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt'
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { User } from './schemas/user.schema';
import { v4 as uuidv4 } from 'uuid';
import { Model } from 'mongoose';
import { ResetToken} from './schemas/reset-token.schema';
import { nanoid } from 'nanoid';
import { MailService } from 'src/services/services/mail.service';



@Injectable()
export class UserService {
  signin: any;
  constructor (
    @InjectModel(User.name) private UserModel:Model<User>,
    @InjectModel(RefreshToken.name) private RefreshTokenModel:Model<RefreshToken>,
    @InjectModel(ResetToken.name) private ResetTokenModel:Model<ResetToken>,
    

  private  jwtService:JwtService,
  private  mailService:MailService,
){}
  async signup(signupData:SignupDto){
    const {email,password,name} = signupData;
    //check if email is in use
    const emilInuse =await this.UserModel.findOne({email,});
    if (emilInuse) {
      throw new BadRequestException('Email already in use')
    };

    // Check if name is in use
    const nameInUse = await this.UserModel.findOne({name,});
    if (nameInUse) {
      throw new BadRequestException('Name already in use');
    }

     
    const hashpassword = await bcrypt.hash(password,10);

    await this.UserModel.create({
      name,
      email,
       
      password:hashpassword,
    });
  }

    async login(credentials:LoginDto){
      const{email,password}=credentials
      //find if user exists by email
      const user= await this.UserModel.findOne({email})
      if(!user){
        throw new UnauthorizedException('Wrong credentials');
      }
       
      const passwordMatch =await bcrypt.compare(password,user.password)
      if(!passwordMatch){
        throw new UnauthorizedException('Wrong credentials');
      }

       //generate jwt token
       return this.generateUserTokens(user._id)
    }

    //change password
    async changePassword(userId, oldPassword: string, newPassword: string) {
      //Find the user
      const user = await this.UserModel.findById(userId);
      if (!user) {
        throw new NotFoundException('User not found...'); 
      }
  
      //Compare the old password with the password in DB
      const passwordMatch = await bcrypt.compare(oldPassword, user.password);
      if (!passwordMatch) {
        throw new UnauthorizedException('Wrong credentials');
      }
  
      //Change user's password
      const newHashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = newHashedPassword;
      await user.save();
    }

    async forgotPassword(email: string) {
      //Check that user exists
      const user = await this.UserModel.findOne({ email });
  
      if (user) {
        //If user exists, generate password reset link
        const expiryDate = new Date();
        expiryDate.setHours(expiryDate.getHours() + 1);
  
        const resetToken = nanoid(64);
        await this.ResetTokenModel.create({
          token: resetToken,
          userId: user._id,
          expiryDate,
        });
        //Send the link to the user by email
        void this.mailService.sendPasswordResetEmail(email, resetToken);
      }
  
      return { message: 'If this user exists, they will receive an email' };
    }

    async resetPassword(nwePassword:string,resetToken:string){
      //find a valid reset token 
      const token = await this.ResetTokenModel.findOneAndReplace({
        token:resetToken,
        expiryDate:{$gte:new Date()},
      })
      if (!token){
        throw new UnauthorizedException('Invalid Link')
      }

      // change user password
      const user=await this.UserModel.findById(token.userId);
      if (!user){
        throw new InternalServerErrorException();
      }
      user.password=await bcrypt.hash(nwePassword,10)
      await user.save();

    }



    async refreshTokens(refreshToken:string){
      const token = await this.RefreshTokenModel.findOneAndDelete({
      token: refreshToken,
      expiryDate: { $gte: new Date() },
    });

    if (!token) {
      throw new UnauthorizedException('Refresh Token is invalid');
    }
    return this.generateUserTokens(token.userId);
    } 


    async generateUserTokens(userId){
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const accessToken = this.jwtService.sign({userId},{expiresIn:'10h'});
      const refreshToken= uuidv4();

      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      await this.storeRefreshToken(refreshToken,userId)

      return{
        accessToken,
        refreshToken,
      };
    }
    async storeRefreshToken(token:string,userId:string){
      // calculate expiry date 3 from now
      const expiryDate=new Date();
      expiryDate.setDate(expiryDate.getDate()+3)
      await this.RefreshTokenModel.updateOne(
        { userId },
        { $set: { expiryDate, token } },
        {
          upsert: true,
        },
      );
    }

}

