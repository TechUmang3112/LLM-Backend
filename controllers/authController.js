const jwt = require("jsonwebtoken");
const { User } = require("./models"); // Sequelize model import
const {
  signupSchema,
  signinSchema,
  acceptCodeSchema,
  changePasswordSchema,
  acceptFPCodeSchema,
} = require("../middlewares/validator");
const { doHash, doHashValidation, hmacProcess } = require("../utils/hashing");
const transport = require("../middlewares/sendMail");

// PostgreSQL Explanation:
// Unlike MongoDB which is document-based, PostgreSQL is relational
// Sequelize is an ORM that lets us work with PostgreSQL using JavaScript objects

exports.signup = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Validation remains the same (Joi validation)
    const { error, value } = signupSchema.validate({ email, password });
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message,
      });
    }

    // PostgreSQL Query: SELECT * FROM users WHERE email = ? LIMIT 1
    const existingUser = await User.findOne({
      where: { email }, // Sequelize syntax for WHERE clause
    });

    if (existingUser) {
      return res.status(401).json({
        success: false,
        message: "User already exists!",
      });
    }

    const hashedPassword = await doHash(password, 12);

    // PostgreSQL Query: INSERT INTO users (email, password) VALUES (?, ?)
    const newUser = await User.create({
      email,
      password: hashedPassword,
    });

    // PostgreSQL Explanation:
    // The created user is now a Sequelize model instance
    // Default scope automatically excludes password field
    res.status(201).json({
      success: true,
      message: "Your account has been created successfully",
      result: newUser,
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

exports.signin = async (req, res) => {
  const { email, password } = req.body;
  try {
    const { error, value } = signinSchema.validate({ email, password });
    if (error) {
      return res.status(401).json({
        success: false,
        message: error.details[0].message,
      });
    }

    // Using custom scope to include password (normally excluded)
    // PostgreSQL Query: SELECT id, email, password, verified FROM users WHERE email = ? LIMIT 1
    const existingUser = await User.scope("withPassword").findOne({
      where: { email },
    });

    if (!existingUser) {
      return res.status(401).json({
        success: false,
        message: "User does not exist!",
      });
    }

    const result = await doHashValidation(password, existingUser.password);
    if (!result) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials!",
      });
    }

    // JWT token generation remains the same
    const token = jwt.sign(
      {
        userId: existingUser.id, // Note: id instead of _id
        email: existingUser.email,
        verified: existingUser.verified,
      },
      process.env.TOKEN_SECRET,
      { expiresIn: "8h" }
    );

    res
      .cookie("Authorization", "Bearer " + token, {
        expires: new Date(Date.now() + 8 * 3600000),
        httpOnly: process.env.NODE_ENV === "production",
        secure: process.env.NODE_ENV === "production",
      })
      .json({
        success: true,
        token,
        message: "Logged in successfully",
      });
  } catch (error) {
    console.error("Signin error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

exports.signout = async (req, res) => {
  // Cookie clearing remains the same
  res.clearCookie("Authorization").status(200).json({
    success: true,
    message: "Logged out successfully",
  });
};

exports.sendVerificationCode = async (req, res) => {
  const { email } = req.body;
  try {
    // Using scope to include verification fields
    const existingUser = await User.scope("withVerification").findOne({
      where: { email },
    });

    if (!existingUser) {
      return res.status(404).json({
        success: false,
        message: "User does not exist!",
      });
    }

    if (existingUser.verified) {
      return res.status(400).json({
        success: false,
        message: "You are already verified!",
      });
    }

    // Cooldown check logic remains the same
    if (existingUser.lastVerificationCodeSentAt) {
      const cooldownEndTime = new Date(
        existingUser.lastVerificationCodeSentAt.getTime() + 30 * 1000
      );

      if (new Date() < cooldownEndTime) {
        const remainingSeconds = Math.ceil(
          (cooldownEndTime - new Date()) / 1000
        );
        return res.status(429).json({
          success: false,
          message: `Please wait ${remainingSeconds} seconds before requesting a new code.`,
        });
      }
    }

    const codeValue = Math.floor(100000 + Math.random() * 900000).toString();
    let info = await transport.sendMail({
      // ... email sending logic remains the same
    });

    if (info.accepted[0] === existingUser.email) {
      const hashedCodeValue = hmacProcess(
        codeValue,
        process.env.HMAC_VERIFICATION_CODE_SECRET
      );

      // PostgreSQL UPDATE query
      await existingUser.update({
        verificationCode: hashedCodeValue,
        verificationCodeValidation: Date.now(),
        lastVerificationCodeSentAt: new Date(),
      });

      return res.status(200).json({
        success: true,
        message: "Code sent!",
      });
    }

    return res.status(400).json({
      success: false,
      message: "Failed to send code!",
    });
  } catch (error) {
    console.error("Verification code error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// 5. VERIFY VERIFICATION CODE
exports.verifyVerificationCode = async (req, res) => {
  const { email, providedCode } = req.body;

  try {
    // Validate input
    const { error } = acceptCodeSchema.validate({ email, providedCode });
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message,
      });
    }

    // Find user with verification fields
    const user = await User.scope("withVerification").findOne({
      where: { email },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found!",
      });
    }

    // Check if already verified
    if (user.verified) {
      return res.status(400).json({
        success: false,
        message: "Account already verified!",
      });
    }

    // Check failed attempts cooldown
    if (user.failedAttempts >= 3) {
      const cooldownEndTime = new Date(
        user.lastFailedAttempt.getTime() + 5 * 60 * 1000
      );
      if (new Date() < cooldownEndTime) {
        const remainingMinutes = Math.ceil(
          (cooldownEndTime - new Date()) / (60 * 1000)
        );
        return res.status(429).json({
          success: false,
          message: `Too many attempts. Try again in ${remainingMinutes} minute(s).`,
        });
      }
      // Reset if cooldown passed
      await user.update({ failedAttempts: 0 });
    }

    // Check code expiration (5 minutes)
    if (Date.now() - user.verificationCodeValidation > 5 * 60 * 1000) {
      return res.status(400).json({
        success: false,
        message: "Verification code expired!",
      });
    }

    // Verify code
    const hashedCode = hmacProcess(
      providedCode.toString(),
      process.env.HMAC_VERIFICATION_CODE_SECRET
    );

    if (hashedCode !== user.verificationCode) {
      // Increment failed attempts
      await user.update({
        failedAttempts: user.failedAttempts + 1,
        lastFailedAttempt: new Date(),
      });

      return res.status(400).json({
        success: false,
        message: "Invalid verification code!",
      });
    }

    // Mark as verified and clear verification data
    await user.update({
      verified: true,
      verificationCode: null,
      verificationCodeValidation: null,
      failedAttempts: 0,
      lastFailedAttempt: null,
    });

    return res.status(200).json({
      success: true,
      message: "Account verified successfully!",
    });
  } catch (error) {
    console.error("Verification error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// 6. CHANGE PASSWORD
exports.changePassword = async (req, res) => {
  const { userId, verified } = req.user; // From JWT
  const { oldPassword, newPassword } = req.body;

  try {
    // Validate input
    const { error } = changePasswordSchema.validate({
      oldPassword,
      newPassword,
    });
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message,
      });
    }

    // Check if user is verified
    if (!verified) {
      return res.status(403).json({
        success: false,
        message: "Unverified users cannot change password!",
      });
    }

    // Find user with password
    const user = await User.scope("withPassword").findByPk(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found!",
      });
    }

    // Verify old password
    const isMatch = await doHashValidation(oldPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Current password is incorrect!",
      });
    }

    // Hash and save new password
    const hashedPassword = await doHash(newPassword, 12);
    await user.update({ password: hashedPassword });

    return res.status(200).json({
      success: true,
      message: "Password changed successfully!",
    });
  } catch (error) {
    console.error("Password change error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// 7. SEND FORGOT PASSWORD CODE
exports.sendForgotPasswordCode = async (req, res) => {
  const { email } = req.body;

  try {
    // Find user with password reset fields
    const user = await User.scope("withPasswordReset").findOne({
      where: { email },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found!",
      });
    }

    // Check cooldown (30 seconds between requests)
    if (user.lastForgotPasswordCodeSentAt) {
      const cooldownEndTime = new Date(
        user.lastForgotPasswordCodeSentAt.getTime() + 30 * 1000
      );

      if (new Date() < cooldownEndTime) {
        const remainingSeconds = calculateRemainingTime(cooldownEndTime);
        return res.status(429).json({
          success: false,
          message: `Please wait ${remainingSeconds} seconds before requesting a new code.`,
        });
      }
    }

    // Generate and send code
    const codeValue = Math.floor(100000 + Math.random() * 900000).toString();
    const info = await transport.sendMail({
      from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
      to: user.email,
      subject: "Password Reset Code",
      html: `...`, // Your email template
    });

    if (info.accepted[0] === user.email) {
      const hashedCode = hmacProcess(
        codeValue,
        process.env.HMAC_VERIFICATION_CODE_SECRET
      );

      await user.update({
        forgotPasswordCode: hashedCode,
        forgotPasswordCodeValidation: Date.now(),
        lastForgotPasswordCodeSentAt: new Date(),
        failedPasswordAttempts: 0, // Reset attempts
      });

      return res.status(200).json({
        success: true,
        message: "Password reset code sent!",
      });
    }

    return res.status(500).json({
      success: false,
      message: "Failed to send password reset code!",
    });
  } catch (error) {
    console.error("Password reset error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// 8. VERIFY FORGOT PASSWORD CODE
exports.verifyForgotPasswordCode = async (req, res) => {
  const { email, providedCode, newPassword } = req.body;

  try {
    // Validate input
    const { error } = acceptFPCodeSchema.validate({
      email,
      providedCode,
      newPassword,
    });
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message,
      });
    }

    // Find user with password reset fields
    const user = await User.scope("withPasswordReset").findOne({
      where: { email },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found!",
      });
    }

    // Check failed attempts cooldown
    if (user.failedPasswordAttempts >= 3) {
      const cooldownEndTime = new Date(
        user.lastFailedPasswordAttempt.getTime() + 5 * 60 * 1000
      );

      if (new Date() < cooldownEndTime) {
        const remainingMinutes = Math.ceil(
          (cooldownEndTime - new Date()) / (60 * 1000)
        );
        return res.status(429).json({
          success: false,
          message: `Too many attempts. Try again in ${remainingMinutes} minute(s).`,
        });
      }
      // Reset if cooldown passed
      await user.update({ failedPasswordAttempts: 0 });
    }

    // Check code expiration (5 minutes)
    if (Date.now() - user.forgotPasswordCodeValidation > 5 * 60 * 1000) {
      return res.status(400).json({
        success: false,
        message: "Password reset code expired!",
      });
    }

    // Verify code
    const hashedCode = hmacProcess(
      providedCode.toString(),
      process.env.HMAC_VERIFICATION_CODE_SECRET
    );

    if (hashedCode !== user.forgotPasswordCode) {
      // Increment failed attempts
      await user.update({
        failedPasswordAttempts: user.failedPasswordAttempts + 1,
        lastFailedPasswordAttempt: new Date(),
      });

      return res.status(400).json({
        success: false,
        message: "Invalid password reset code!",
      });
    }

    // Update password and clear reset data
    const hashedPassword = await doHash(newPassword, 12);
    await user.update({
      password: hashedPassword,
      forgotPasswordCode: null,
      forgotPasswordCodeValidation: null,
      failedPasswordAttempts: 0,
      lastFailedPasswordAttempt: null,
    });

    return res.status(200).json({
      success: true,
      message: "Password reset successfully!",
    });
  } catch (error) {
    console.error("Password reset verification error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
