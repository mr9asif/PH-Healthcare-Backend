import { AuthProvider } from "../../../generated/prisma/enums";

export interface OAuthProfile {
  sub: string;
  provider: AuthProvider;
  providerAccountId: string;
  email: string;
  name: string;
  avatar?: string;
}

export interface GoogleLoginInput {
  credential: string;
}
