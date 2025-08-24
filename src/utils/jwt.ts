import jwt, { SignOptions } from "jsonwebtoken";

export const signAccessToken = (userId: string) => {
  const payload = { id: userId };
  const options: SignOptions = {
    expiresIn: (process.env.JWT_EXPIRY as jwt.SignOptions["expiresIn"]) || "15m",
  };

  return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET as string, options);
};

export const signRefreshToken = (userId: string) => {
  const payload = { id: userId };
  const options: SignOptions = {
    expiresIn: (process.env.JWT_REFRESH_EXPIRY as jwt.SignOptions["expiresIn"]) || "7d",
  };

  return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET as string, options);
};
