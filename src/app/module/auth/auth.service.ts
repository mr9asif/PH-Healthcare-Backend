import bcrypt from "bcryptjs";
import { JwtPayload, SignOptions } from "jsonwebtoken";
import {
  AuthProvider,
  Role,
  UserStatus,
} from "../../../generated/prisma/enums";
import config from "../../config";
import { prisma } from "../../lib/prisma";
import { jwtUtils } from "../../utils/jwt";
import {
  IGoogleLogin,
  ILoginUserPayload,
  IRegisterPatientPayload,
  IRequestUser,
} from "./auth.interface";
import { verifyGoogleIdToken } from "./provider/google.provider";

const registerPatient = async (payload: IRegisterPatientPayload) => {
  const { name, password } = payload;
  const email = payload.email.trim().toLowerCase();

  const isUserExists = await prisma.user.findUnique({
    where: { email },
  });

  if (isUserExists) {
    throw new Error("User with this email already exists");
  }

  const hashedPassword = await bcrypt.hash(password, 8);

  const createdUser = await prisma.user.create({
    data: {
      name,
      email,
      password: hashedPassword,
      role: Role.PATIENT,
      status: UserStatus.ACTIVE,
      emailVerified: false,
      patient: {
        create: { name, email },
      },
    },
    omit: { password: true },
    include: { patient: true },
  });

  const { patient, ...user } = createdUser;
  const jwtPayload = {
    userId: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };

  const accessToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_access_secret,
    config.jwt_access_expires_in as SignOptions,
  );

  const refreshToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_refresh_secret,
    config.jwt_refresh_expires_in as SignOptions,
  );

  return {
    user,
    patient,
    accessToken,
    refreshToken,
  };
};

const loginUser = async (payload: ILoginUserPayload) => {
  const { password } = payload;
  const email = payload.email.trim().toLowerCase();

  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user) {
    throw new Error("User not found");
  }

  if (user.status === UserStatus.BLOCKED) {
    throw new Error("User is blocked");
  }

  if (user.isDeleted || user.status === UserStatus.DELETED) {
    throw new Error("User is deleted");
  }

  // Google-only account
  if (!user.password) {
    throw new Error(
      "This account was created with Google. Please login with Google.",
    );
  }

  const isPasswordMatched = await bcrypt.compare(password, user.password);

  if (!isPasswordMatched) {
    throw new Error("Invalid credentials");
  }

  const jwtPayload = {
    userId: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };

  const accessToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_access_secret,
    config.jwt_access_expires_in as SignOptions,
  );

  const refreshToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_refresh_secret,
    config.jwt_refresh_expires_in as SignOptions,
  );

  return {
    accessToken,
    refreshToken,
  };
};
const getMe = async (user: IRequestUser) => {
  const isUserExists = await prisma.user.findUnique({
    where: {
      id: user.userId,
    },
    include: {
      patient: true,
    },
    omit: {
      password: true,
    },
  });

  if (!isUserExists) {
    throw new Error("User not found");
  }

  return isUserExists;
};

const refreshToken = async (token: string) => {
  const verifiedRefreshToken = jwtUtils.verifyToken(
    token,
    config.jwt_refresh_secret,
  );

  if (!verifiedRefreshToken.success || !verifiedRefreshToken.data) {
    throw new Error(
      config.node_env === "development"
        ? verifiedRefreshToken.error
        : "Invalid refresh token",
    );
  }

  const data = verifiedRefreshToken.data as JwtPayload;

  const user = await prisma.user.findUnique({
    where: { id: data.userId },
  });

  if (!user || user.isDeleted || user.status !== UserStatus.ACTIVE) {
    throw new Error("User is inactive or not found");
  }

  const jwtPayload = {
    userId: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };

  const accessToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_access_secret,
    config.jwt_access_expires_in as SignOptions,
  );

  const refreshToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_refresh_secret,
    config.jwt_refresh_expires_in as SignOptions,
  );

  return {
    accessToken,
    refreshToken,
  };
};

const googleLogin = async (payload: IGoogleLogin) => {
  // ============================================
  // 1. Verify Google ID Token
  // ============================================

  const googleIdTokenPayload = await verifyGoogleIdToken(payload.IdToken);

  // Google identity
  const googleId = googleIdTokenPayload.sub;

  const email = googleIdTokenPayload.email.trim().toLowerCase();

  const name = googleIdTokenPayload.name;

  // ============================================
  // 2. Check whether this Google account
  //    is already linked
  // ============================================

  const existingGoogleAccount = await prisma.account.findUnique({
    where: {
      provider_providerAccountId: {
        provider: AuthProvider.GOOGLE,
        providerAccountId: googleId,
      },
    },

    include: {
      user: {
        include: {
          patient: true,
        },
      },
    },
  });

  let user;

  // ============================================
  // 3. Google account already exists
  // ============================================

  if (existingGoogleAccount) {
    user = existingGoogleAccount.user;
  }

  // ============================================
  // 4. Google account doesn't exist
  // ============================================

  if (!user) {
    // Find existing credential-based user
    const existingCredentialUser = await prisma.user.findUnique({
      where: {
        email,
      },

      include: {
        patient: true,
      },
    });

    // ============================================
    // 5. Existing credential user found
    // ============================================

    if (existingCredentialUser) {
      // Email must already be verified
      if (!existingCredentialUser.emailVerified) {
        throw new Error("Email Not Verified");
      }

      // Check blocked
      if (existingCredentialUser.status === UserStatus.BLOCKED) {
        throw new Error("User Is Blocked");
      }

      // Check deleted
      if (
        existingCredentialUser.isDeleted ||
        existingCredentialUser.status === UserStatus.DELETED
      ) {
        throw new Error("User Is Deleted");
      }

      // Link Google account
      await prisma.account.create({
        data: {
          provider: AuthProvider.GOOGLE,
          providerAccountId: googleId,
          userId: existingCredentialUser.id,
        },
      });

      user = existingCredentialUser;
    }

    // ============================================
    // 6. No existing user
    //    → Create new Google user
    // ============================================

    if (!user) {
      user = await prisma.user.create({
        data: {
          name,
          email,

          // Google-only user
          password: null,

          role: Role.PATIENT,
          status: UserStatus.ACTIVE,

          // Google verified the identity
          emailVerified: true,

          patient: {
            create: {
              name,
              email,
            },
          },

          accounts: {
            create: {
              provider: AuthProvider.GOOGLE,
              providerAccountId: googleId,
            },
          },
        },

        include: {
          patient: true,
        },
      });
    }
  }

  // ============================================
  // 7. Final user validation
  // ============================================

  if (!user) {
    throw new Error("User Not Found");
  }

  if (user.status === UserStatus.BLOCKED) {
    throw new Error("User Is Blocked");
  }

  if (user.isDeleted || user.status === UserStatus.DELETED) {
    throw new Error("User Is Deleted");
  }

  // ============================================
  // 8. Create JWT payload
  // ============================================

  const jwtPayload = {
    userId: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };

  // ============================================
  // 9. Create Access Token
  // ============================================

  const accessToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_access_secret,
    config.jwt_access_expires_in as SignOptions,
  );

  // ============================================
  // 10. Create Refresh Token
  // ============================================

  const refreshToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_refresh_secret,
    config.jwt_refresh_expires_in as SignOptions,
  );

  // ============================================
  // 11. Return authentication result
  // ============================================

  return {
    accessToken,
    refreshToken,
  };
};

export const AuthService = {
  registerPatient,
  loginUser,
  getMe,
  refreshToken,
  googleLogin,
};
