import nodemailer from "nodemailer";
import config from "../config";
export const transporter = nodemailer.createTransport({
  service: config.smtp_sender,
  auth: {
    user: config.smtp_user,
    pass: config.smtp_password,
  },
});
