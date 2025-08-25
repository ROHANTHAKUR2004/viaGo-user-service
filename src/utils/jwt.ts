import jwt, { SignOptions } from "jsonwebtoken";

export const signAccessToken = (userId: string) => {
  const payload = { id: userId };
  const options: SignOptions = {
    expiresIn: (process.env.JWT_EXPIRY as jwt.SignOptions["expiresIn"]) || "15m",
  };

  return jwt.sign(payload, process.env.JWT_SECRET as string, options);
};

