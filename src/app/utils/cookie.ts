import { CookieOptions } from "express";
import config from "../config";

export const accessTokenCookieOptions: CookieOptions = {
  httpOnly: true,
  secure: config.node_env === "production",
  sameSite: config.node_env === "production" ? "none" : "lax",
  maxAge: 15 * 60 * 1000,
  path: "/",
};

export const refreshTokenCookieOptions: CookieOptions = {
  httpOnly: true,
  secure: config.node_env === "production",
  sameSite: config.node_env === "production" ? "none" : "lax",
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: "/",
};
