import { NextFunction, Request, Response } from "express";
import asyncHandler from "../utils/asynHandler";
import ApiError from "../utils/ApiError";
import User from "../model/user.model";
import ApiResponse from "../utils/ApiResponse";
import crypto from "crypto";
import { sendEmail } from "../utils/sendEmail";
import { signAccessToken } from "../utils/jwt";


export const magicLinkRateLimit = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress || "unknown";

    if (!email) return next(new ApiError(400, "Email is required"));

    const user = await User.findOne({ email });

    if (user) {
      const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
      const recentRequests = user.magicLinkRequests.filter(
        (r) => r.timestamp > fifteenMinutesAgo && r.ipAddress === ipAddress
      );

      if (recentRequests.length >= 3)
        return next(
          new ApiError(429, "Too many magic link requests. Please try again later.")
        );

      user.magicLinkRequests.push({ timestamp: new Date(), ipAddress });

      if (user.magicLinkRequests.length > 10)
        user.magicLinkRequests = user.magicLinkRequests.slice(-10);

      await user.save();
    }

    next();
  }
);

export const requestMagicLink = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;

    if (!email) return next(new ApiError(400, "Email is required"));

    const user = await User.findOne({ email, isVerified: true }).select(
      "+magicLoginToken +magicLoginExpires +magicLinkRequests"
    );

    if (!user) {
      console.log(`Magic link requested for non-existent email: ${email}, IP: ${ipAddress}`);
      return res.json(new ApiResponse(200, null, "If the email exists, a magic link has been sent"));
    }

  
    const magicToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto.createHash("sha256").update(magicToken).digest("hex");
    const magicTokenExpires = new Date(Date.now() + 15 * 60 * 1000); 

    user.magicLoginToken = hashedToken;
    user.magicLoginExpires = magicTokenExpires;
    await user.save();

    const magicLink = `${process.env.FRONTEND_URL}/auth/magic-login?token=${magicToken}&email=${encodeURIComponent(email)}`;

    try {
      await sendEmail({
        to: email,
        subject: "Your Magic Login Link",
        text: `Login using this link: ${magicLink}`,
        html: `<a href="${magicLink}">Login</a>`,
      });

      console.log(`Magic link requested for email: ${email}, IP: ${ipAddress}`);
      res.json(new ApiResponse(200, null, "If the email exists, a magic link has been sent"));
    } catch (error) {
      user.magicLoginToken = undefined;
      user.magicLoginExpires = undefined;
      await user.save();
      console.error("Magic link email error:", error);
      throw new ApiError(500, "Email could not be sent");
    }
  }
);

export const verifyMagicLink = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
   
    const { token, email } = req.query as { token?: string; email?: string };

    if (!token || !email) return next(new ApiError(400, "Token and email are required"));

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      email,
      magicLoginToken: hashedToken,
      magicLoginExpires: { $gt: new Date() },
      isVerified: true,
    }).select("+magicLoginToken +magicLoginExpires");

    if (!user) return next(new ApiError(400, "Magic link is invalid or has expired"));

    
    user.magicLoginToken = undefined;
    user.magicLoginExpires = undefined;
    user.lastLogin = new Date();
    user.loginCount += 1;
    await user.save();

   
    const authToken = signAccessToken(user.id);

    res.cookie("token", authToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, 
    });

    res.status(200).json(
      new ApiResponse(200, { token: authToken, user }, "Login successful")
    );
  }
);
