import mongoose, { Document, Schema } from "mongoose";
export interface IUser extends Document {
  username: string;
  email: string;
  password: string;
  isVerified: boolean;
  otp?: string;
  otpExpires?: Date;
  resetPasswordToken?: string;
  resetPasswordExpires?: Date;
  magicLoginToken?: string;
  magicLoginExpires?: Date;
  lastLogin?: Date;
  loginCount: number;
  magicLinkRequests: {
    timestamp: Date;
    ipAddress: string;
  }[];
 
}


const UserSchema = new Schema<IUser>(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 30,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    otp: {
      type: String,
    },
    otpExpires: {
      type: Date,
    },
    resetPasswordToken: {
      type: String,
    },
    resetPasswordExpires: {
      type: Date,
    },
    magicLoginToken: {
      type: String,
      select: false,
    },
    magicLoginExpires: {
      type: Date,
      select: false,
    },
    lastLogin: {
      type: Date,
    },
    loginCount: {
      type: Number,
      default: 0,
    },
    magicLinkRequests: [{
      timestamp: {
        type: Date,
        default: Date.now
      },
      ipAddress: String
    }]
  },
  { timestamps: true }
);


const User = mongoose.model<IUser>("User", UserSchema);
export default User;
