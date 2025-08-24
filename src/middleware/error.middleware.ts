import { Request, Response, NextFunction } from "express";
import ApiError from "../utils/ApiError";

const errorMiddleware = (err: any, _req: Request, res: Response, _next: NextFunction) => {
  const status = err instanceof ApiError ? err.statusCode : 500;
  const message = err instanceof ApiError ? err.message : "Internal Error";
  console.log("error is " , message);
  if (status === 500) console.error(err);
  res.status(status).json({ success: false, message });
};

export default errorMiddleware;
