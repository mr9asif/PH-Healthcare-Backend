import { v2 as Cloudinary } from "cloudinary";
import dotenv from "dotenv";
import config from "../config";

dotenv.config();

Cloudinary.config({
  cloud_name: config.cloudinary_name,
  api_key: config.cloudinary_api_key,
  api_secret: config.cloudinary_secret_key,
  secure: true, // Forces the SDK to generate secure HTTPS URLs
});

export const cloudinary = Cloudinary;
