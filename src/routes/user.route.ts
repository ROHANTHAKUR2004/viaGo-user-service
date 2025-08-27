import { Router } from "express";
import { changePassword, forgotPassWord, loginUser, logoutUser,  registerUser, resendOtp, resetPassWord, verifyEmail } from "../controllers/user.controller";

import { magicLinkRateLimit, requestMagicLink, verifyMagicLink } from "../controllers/user.magic";
import { getLinkedAccounts, googleAuth, googleAuthCallback, unlinkGoogleAccount } from "../controllers/social-auth.controller";
import { isAuthenticated } from "../middleware/auth.middleware";

const userRouter = Router();


userRouter.post("/register",registerUser )
userRouter.post("/verfiy-email", verifyEmail);
userRouter.post("/resend-otp", resendOtp);


userRouter.post("/login", loginUser);
userRouter.post("/forgot-password", forgotPassWord)
userRouter.post("/reset-password/:token", resetPassWord);
userRouter.post("/changepasword ", changePassword )


userRouter.post("/logout", isAuthenticated, logoutUser);


userRouter.post("/magic-link/request", magicLinkRateLimit, requestMagicLink);
userRouter.post("/magic-link/verify", verifyMagicLink);


// googel auth routes
userRouter.get("/auth/google", googleAuth);


userRouter.get("/auth/google/callback", googleAuthCallback);

userRouter.post("/auth/unlink/google", isAuthenticated, unlinkGoogleAccount);


userRouter.get("/auth/linked-accounts", isAuthenticated, getLinkedAccounts);

export default userRouter;