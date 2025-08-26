import { NextFunction, Request, Response } from "express";
import asyncHandler from "../utils/asynHandler";
import ApiError from "../utils/ApiError";
import bcrypt from "bcryptjs";
import User from "../model/user.model";
import { sendEmail } from "../utils/sendEmail";
import ApiResponse from "../utils/ApiResponse";
import crypto from "crypto";
import jwt from "jsonwebtoken";

import {  JWT_PAYLOAD } from "../middleware/auth.middleware";

export const registerUser = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      throw new ApiError(400, "username, email, password are required");

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing?.isVerified)
      return next(new ApiError(409, "Username or email already in use"));
    else if (existing && !existing?.isVerified) {
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

      return;
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
  }
);

export const verifyEmail = asyncHandler(async (req: Request, res: Response) => {
  const { email, otp } = req.body;
  if (!email || !otp) throw new ApiError(400, "email and otp are required");

  const user = await User.findOne({ email });
  if (!user) throw new ApiError(404, "User not found");
  if (user.isVerified) throw new ApiError(400, "Already verified");
  if (!user.otp || !user.otpExpires)
    throw new ApiError(400, "OTP not requested");
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

export const loginUser = asyncHandler(async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password)
    throw new ApiError(401, "email and password required");

  const user = await User.findOne({ email });
  if (!user) throw new ApiError(404, "User Not found");

  if (!user.isVerified) throw new ApiError(400, "EMAIL IS NOT VERFIED");

  const ismatch = await bcrypt.compare(password, user.password);
  if (!ismatch) throw new ApiError(401, "invalid password");

  const token = jwt.sign(
    {
      id: user.id,
    } as JWT_PAYLOAD,
    process.env.JWT_SECRET as string,
    { expiresIn: parseInt(process.env.JWT_EXPIRE as string) }
  );

  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.json(new ApiResponse(200, { token }, "Login Succesfully"));
});

export const logoutUser = asyncHandler(
  async (req: Request, res: Response) => {
    const userId = req.user?.id;

    if (!userId) {
      throw new ApiError(404, "Already logged out");
    }

    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    return res.json(new ApiResponse(200, {}, "Logout successful"));
  }
);

export const forgotPassWord = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email } = req.body;

    if (!email) {
      throw new ApiError(400, "Email is required");
    }

    const user = await User.findOne({ email });
    if (!user?.isVerified || !user) {
      return res.json(
        new ApiResponse(
          200,
          null,
          "User not verified or does not exist, link has been sent"
        )
      );
    }

    const resetToken = crypto.randomBytes(32).toString("hex");

    const resetPasswordToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    const resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);

    user.resetPasswordToken = resetPasswordToken;
    user.resetPasswordExpires = resetPasswordExpires;

    await user.save();

    try {
      const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

      await sendEmail({
        to: email,
        subject: "Password Reset Request",
        text: `ink has been sent ${resetToken}`,
        html: `
        <p>You requested a password reset</p>
        <p>Click below link to reset your password:</p>
        <a href="${resetUrl}" target="_blank">Reset Password</a>
        <p>This link expires in 15 minutes.</p>
      `,
      });

      res.json(
        new ApiResponse(
          200,
          null,
          "If the email exists, a reset link has been sent"
        )
      );
    } catch (error) {
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();

      throw new ApiError(500, "Email could not be sent");
    }
  }
);

export const resetPassWord = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    if (!token || !newPassword) {
      throw new ApiError(400, "Token and new password are required");
    }

    if (newPassword.length < 6) {
      throw new ApiError(400, "Password must be at least 6 characters");
    }

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user || !user.isVerified) {
      throw new ApiError(400, "Token is invalid or expired");
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    res.json(
      new ApiResponse(200, null, "Password has been reset successfully")
    );
  }
);

export const changePassword = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user?.id;

    if (!currentPassword || !newPassword) {
      throw new ApiError(400, "Current and new password are required");
    }

    if (newPassword.length < 6) {
      throw new ApiError(400, "New password must be at least 6 characters");
    }
    const user = await User.findById(userId);
    if (!user || !user.isVerified) {
      throw new ApiError(404, "User not found");
    }

    const isCurrentPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password
    );
    if (!isCurrentPasswordValid) {
      throw new ApiError(400, "Current password is incorrect");
    }
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      throw new ApiError(
        400,
        "New password must be different from current password"
      );
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json(new ApiResponse(200, null, "Password changed successfully"));
  }
);
