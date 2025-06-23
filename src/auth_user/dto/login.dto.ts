import {  IsEmail, IsString, MaxLength, MinLength } from "class-validator";

export class LoginDto {

    //Password
    @IsString({message:"Password Must Be A String"})
    @MinLength(10,{message:'Password Must Be At Least 10 Characters'})
    @MaxLength(20,{message:"Password Must Be At Most 20 Characters"})
    password: string;
    //Email
    @IsString({message:"Email Must Be A String"})
    @MinLength(0,{message:"Email Must Be Required"})
    @IsEmail({},{message:"Email Is Not Vaid"})
    email: string;
}
