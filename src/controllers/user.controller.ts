
import { NextFunction, Request, Response } from "express";
import asyncHandler from "../utils/asynHandler";
import ApiError from "../utils/ApiError";
import bcrypt from "bcryptjs";
import User from "../model/user.model";
import { sendEmail } from "../utils/sendEmail";
import ApiResponse from "../utils/ApiResponse";
import jwt from "jsonwebtoken";

import { signAccessToken, signRefreshToken } from "../utils/jwt";
import { AuthRequest } from "../middleware/auth.middleware";


export const registerUser = asyncHandler(async (req: Request, res: Response, next : NextFunction) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    throw new ApiError(400, "username, email, password are required");

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

  const existing = await User.findOne({ $or: [{ email }, { username }] });
  if (existing?.isVerified)  return next(new ApiError(409, "Username or email already in use"));

  else if(existing && !existing?.isVerified ){
     
       existing.otp = otp;
       existing.otpExpires = otpExpires;

       await sendEmail({
       to: email,
      subject: "Verify your email",
      text: `Your OTP is ${otp}. It expires in 10 minutes.`,
      html: `<p>Your OTP is <b>${otp}</b>. It expires in 10 minutes.</p>`,
  });

  
     res
    .status(201)
    .json(new ApiResponse(201, null, "Registered. OTP sent to email."));

    return ;

     
  }

  const hashed = await bcrypt.hash(password, 10);

  await User.create({
    username,
    email,
    password: hashed,
    isVerified: false,
    otp,
    otpExpires,
  });

  await sendEmail({
    to: email,
    subject: "Verify your email",
    text: `Your OTP is ${otp}. It expires in 10 minutes.`,
    html: `<p>Your OTP is <b>${otp}</b>. It expires in 10 minutes.</p>`,
  });

  res
    .status(201)
    .json(new ApiResponse(201, null, "Registered. OTP sent to email."));
});



export const verifyEmail = asyncHandler(async (req: Request, res: Response) => {
  const { email, otp } = req.body;
  if (!email || !otp) throw new ApiError(400, "email and otp are required");

  const user = await User.findOne({ email });
  if (!user) throw new ApiError(404, "User not found");
  if (user.isVerified) throw new ApiError(400, "Already verified");
  if (!user.otp || !user.otpExpires) throw new ApiError(400, "OTP not requested");
  if (user.otp !== otp) throw new ApiError(400, "Invalid OTP");
  if (user.otpExpires < new Date()) throw new ApiError(400, "OTP expired");

  user.isVerified = true;
  user.otp = undefined;
  user.otpExpires = undefined;
  await user.save();

  res.json(new ApiResponse(200, null, "Email verified successfully"));
});



export const resendOtp = asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) throw new ApiError(400, "email is required");

  const user = await User.findOne({ email });
  if (!user) throw new ApiError(404, "User not found");
  if (user.isVerified) throw new ApiError(400, "User already verified");

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  user.otp = otp;
  user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
  await user.save();

  await sendEmail({
    to: email,
    subject: "Your new OTP",
    text: `Your OTP is ${otp}. It expires in 10 minutes.`,
    html: `<p>Your OTP is <b>${otp}</b>. It expires in 10 minutes.</p>`,
  });

  res.json(new ApiResponse(200, null, "OTP resent"));
});



export const loginUser = asyncHandler(async (req : Request, res : Response) => {
     
     const {email , password} = req.body;

     if(!email || !password) throw new ApiError(401, "email and password required");

     const  user = await User.findOne({email});
     if(!user) throw new ApiError(404, "User Not found");

     if(!user.isVerified) throw new ApiError(400,"EMAIL IS NOT VERFIED");

     const ismatch = await bcrypt.compare(password, user.password);
     if(!ismatch) throw new ApiError(401 , "invalid password");


     const token = signAccessToken(user.id);
    
     res.cookie("token", token, {
        httpOnly : true,
        sameSite : "strict",
        maxAge : 7 * 24 * 60 * 60 * 1000, 
     })


     res.json(new ApiResponse(200, {token}, "Login Succesfully" ));

});



export const refreshAccessToken = asyncHandler(async (req: Request, res: Response) => {
  const token = req.cookies.refreshToken;

  if (!token) throw new ApiError(401, "Refresh token missing");

  try {
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET!) as { id: string };

    const newAccessToken = signAccessToken(decoded.id);

    return res.json(
      new ApiResponse(200, { accessToken: newAccessToken }, "Access token refreshed")
    );
  } catch (error) {
    console.log("iserror" , error);
    throw new ApiError(403, "Invalid or expired refresh token");
  }
});


export const logoutUser = asyncHandler(async (req: AuthRequest, res: Response) => {
  const userId = req.user?.id;

  if (!userId) {
    throw new ApiError(404, "Already logged out");
  }


  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });

  return res.json(new ApiResponse(200, {}, "Logout successful"));
});




