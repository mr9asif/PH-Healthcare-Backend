import { OAuth2Client } from "google-auth-library";

import { AuthProvider } from "../../../../generated/prisma/enums";
import config from "../../../config";
import { OAuthProfile } from "../auth.types";

const googleClient = new OAuth2Client(config.google_client_id);

export const verifyGoogleIdToken = async (
  idToken: string,
): Promise<OAuthProfile> => {
  const ticket = await googleClient.verifyIdToken({
    idToken,
    audience: config.google_client_id,
  });

  const payload = ticket.getPayload();

  if (!payload) {
    throw new Error("Invalid Google ID token");
  }

  if (!payload.sub) {
    throw new Error("Google account ID not found");
  }

  if (!payload.email) {
    throw new Error("Google email not found");
  }

  if (payload.email_verified !== true) {
    throw new Error("Google email is not verified");
  }

  return {
    sub: payload.sub,
    provider: AuthProvider.GOOGLE,
    providerAccountId: payload.sub,
    email: payload.email,
    name: payload.name ?? "Google User",
    avatar: payload.picture,
  };
};
