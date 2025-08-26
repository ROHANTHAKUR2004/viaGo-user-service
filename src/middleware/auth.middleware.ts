import { NextFunction, Response, Request } from "express";
import jwt, { JwtPayload as DefaultJwtPayload, JwtPayload } from "jsonwebtoken";
import ApiError from "../utils/ApiError"; // your custom error class
import User from "../model/user.model";


export interface JWT_PAYLOAD extends JwtPayload {
  id: string;
  
}


export const isAuthenticated = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const token = req.cookies?.token || req.headers.authorization?.split(" ")[1];

    if (!token) {
      return next(new ApiError(401, "Unauthorized – No token provided"));
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as JWT_PAYLOAD;
    if(!decoded){
      return next(new ApiError(401 , "Please Login to Continue your token has been expired "))
    }

   
    req.user = decoded;

    next();
  } catch (error) {
    console.error("JWT Error:", error);
    return next(new ApiError(401, "Unauthorized – Invalid or expired token"));
  }
};
