import { Router } from "express";
import { changePassword, forgotPassWord, loginUser, logoutUser,  registerUser, resendOtp, resetPassWord, verifyEmail } from "../controllers/user.controller";
import auth from "../middleware/auth.middleware";
import { magicLinkRateLimit, requestMagicLink, verifyMagicLink } from "../controllers/user.magic";

const userRouter = Router();


userRouter.post("/register",registerUser )
userRouter.post("/verfiy-email", verifyEmail);
userRouter.post("/resend-otp", resendOtp);


userRouter.post("/login", loginUser);
userRouter.post("/forgot-password", forgotPassWord)
userRouter.post("/reset-password/:token", resetPassWord);
userRouter.post("/changepasword ", changePassword )


userRouter.post("/logout", auth, logoutUser);


userRouter.post("/magic-link/request", magicLinkRateLimit, requestMagicLink);
userRouter.post("/magic-link/verify", verifyMagicLink);


export default userRouter;