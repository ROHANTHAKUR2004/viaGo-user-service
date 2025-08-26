import passport from "passport";
import asyncHandler from "../utils/asynHandler";
import { NextFunction, Request, Response } from "express";
import ApiError from "../utils/ApiError";

 import ApiResponse from "../utils/ApiResponse";
import User from "../model/user.model";
import { JWT_PAYLOAD } from "../middleware/auth.middleware";
import jwt from 'jsonwebtoken'

export const googleAuth = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    passport.authenticate("google", {
      scope: ["profile", "email"],
      session: false,
    })(req, res, next);
  }
);

export const googleAuthCallback = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    passport.authenticate(
      "google",
      { session: false, failureRedirect: process.env.LOGIN_FAILURE_REDIRECT || "/login" },
      async (err: any, user: any) => {
        if (err || !user) {
          return next(new ApiError(401, "Google authentication failed"));
        }

        try {
        const token = jwt.sign(
           {
             id: user.id,
           } as JWT_PAYLOAD,
           process.env.JWT_SECRET as string,
           { expiresIn: parseInt(process.env.JWT_EXPIRE as string) }
         );

          // Set cookie
          res.cookie("token", token, {
            httpOnly: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000,
            secure: process.env.NODE_ENV === "production",
          });

          // Redirect to frontend with token
          res.redirect(
           ` ${process.env.FRONTEND_URL}/auth/success?token=${token}`
          );
        } catch (error) {
          return next(new ApiError(500, "Error generating token"));
        }
      }
    )(req, res, next);
  }
);

export const getLinkedAccounts = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const userId = req.user?.id;

    if (!userId) {
      throw new ApiError(401, "Authentication required");
    }

    const user = await User.findById(userId);
    if (!user) {
      throw new ApiError(404, "User not found");
    }

    const providers = user.authProvides.map(ap => ap.provider);
    res.json(new ApiResponse(200, { providers }, "Linked accounts retrieved"));
  }
);

export const unlinkGoogleAccount = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const userId = req.user?.id;

    if (!userId) {
      throw new ApiError(401, "Authentication required");
    }

    const user = await User.findById(userId);
    if (!user) {
      throw new ApiError(404, "User not found");
    }

    // Check if user has other authentication methods
    const hasPassword = !!user.password;
    const hasOtherProviders = user.authProvides.some(ap => ap.provider !== "google");

    if (!hasPassword && user.authProvides.length <= 1) {
      throw new ApiError(400, "Cannot unlink the only authentication method");
    }

    // Remove Google auth provider
    user.authProvides = user.authProvides.filter(ap => ap.provider !== "google");
    await user.save();

    res.json(new ApiResponse(200, null, "Google account unlinked successfully"));
  }
);