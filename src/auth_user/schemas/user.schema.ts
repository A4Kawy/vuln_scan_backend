
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

@Schema({timestamps:true})
export class User {
  @Prop({
    type:String,
    required:true, 
    min:[3,"Name Must Be At Least 3 Characters"],
    max:[20,"Name Must Be At Most 20 Characters"]
})
  name: string;
  @Prop({
    required:true, 
    type:String,
    unique:true
})
  email: string;
  @Prop({
    type:String,
    required:true, 
    min:[10,"Password Must Be At Least 10 Characters"],
    max:[20,"Password Must Be At Most 20 Characters"],
    // match: [/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
        // 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character']
})
  password: string;

}

export const UserSchema = SchemaFactory.createForClass(User);
