import { Request, Response, NextFunction } from "express";
import { verify } from "jsonwebtoken";
import { fromUnixTime } from "date-fns";
import authConfig from "../config/auth";

interface TokenPayload {
  iat: number;
  exp: number;
  sub: string;
}

export default function ensureAuthenticated(
  request: Request,
  response: Response,
  next: NextFunction
): void {
  //validação do token
  const authHeader = request.headers.authorization;

  if (!authHeader) {
    throw new Error("JWT token is missing");
  }
  const [, token] = authHeader.split(" ");

  try {
    const decoded = verify(token, authConfig.jwt.secret);
    const { sub } = decoded as TokenPayload;
    //modificar tipos da biblioteca

    request.user = {
      id: sub,
    };

    return next();
  } catch {
    throw new Error("Invalid JWT token");
  }
}
