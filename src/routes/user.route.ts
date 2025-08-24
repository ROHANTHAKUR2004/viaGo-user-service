import { Router } from "express";
import { loginUser, logoutUser, refreshAccessToken, registerUser, resendOtp, verifyEmail } from "../controllers/user.controller";
import auth from "../middleware/auth.middleware";

const userRouter = Router();


userRouter.post("/register",registerUser )
userRouter.post("/verfiy-email", verifyEmail);
userRouter.post("/resend-otp", resendOtp);


userRouter.post("/login", loginUser);
userRouter.post("/refresh-token", refreshAccessToken);

userRouter.post("/logout", auth, logoutUser);


export default userRouter;