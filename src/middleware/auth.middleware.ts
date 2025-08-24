import { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload as DefaultJwtPayload } from "jsonwebtoken";
import ApiError from "../utils/ApiError";

export interface JwtPayload extends DefaultJwtPayload {
  id: string;
  email?: string;
}

export interface AuthRequest extends Request {
  user?: JwtPayload;
}

const auth = (req: AuthRequest, _res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    let token: string | undefined;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    } else if (req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      throw new ApiError(401, "Unauthorized – No token provided");
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
    req.user = decoded;

    next();
  } catch (error) {
    console.log(error);
    throw new ApiError(401, "Unauthorized – Invalid or expired token");
  }
};

export default auth;
