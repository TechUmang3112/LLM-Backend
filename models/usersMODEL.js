const { DataTypes } = require("sequelize");
const { doHash, hmacProcess } = require("../utils/hashing");
const crypto = require("crypto");

module.exports = (sequelize) => {
  const User = sequelize.define(
    "User",
    {
      // UUID primary key for better security and distribution
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
        allowNull: false,
        validate: {
          isUUID: 4,
        },
      },

      // Email field with robust validation
      email: {
        type: DataTypes.STRING(255), // Explicit length for PostgreSQL optimization
        allowNull: false,
        unique: {
          name: "users_email_unique",
          msg: "This email is already registered",
        },
        validate: {
          notEmpty: {
            msg: "Email cannot be empty",
          },
          isEmail: {
            msg: "Please provide a valid email address",
          },
          len: {
            args: [5, 255],
            msg: "Email must be between 5 and 255 characters",
          },
          isLowercase: true,
        },
        set(value) {
          // Automatic email normalization
          this.setDataValue("email", value.toString().toLowerCase().trim());
        },
      },

      // Password field with automatic hashing
      password: {
        type: DataTypes.STRING(60), // bcrypt hash length
        allowNull: false,
        validate: {
          notEmpty: {
            msg: "Password cannot be empty",
          },
          len: {
            args: [8, 72], // bcrypt maximum length
            msg: "Password must be between 8 and 72 characters",
          },
          isStrongPassword(value) {
            if (
              !/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])/.test(value)
            ) {
              throw new Error(
                "Password must contain at least one lowercase, uppercase, number, and special character"
              );
            }
          },
        },
        async set(value) {
          // Automatic password hashing before saving
          if (value) {
            this.setDataValue("password", await doHash(value, 12));
          }
        },
      },

      // Account verification fields
      verified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        allowNull: false,
      },
      verificationCode: {
        type: DataTypes.STRING(64), // HMAC-SHA256 length
        allowNull: true,
      },
      verificationCodeValidation: {
        type: DataTypes.BIGINT, // Large number for timestamp storage
        allowNull: true,
      },
      lastVerificationCodeSentAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },

      // Failed attempt tracking
      failedAttempts: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
        validate: {
          min: 0,
        },
      },
      lastFailedAttempt: {
        type: DataTypes.DATE,
        allowNull: true,
      },

      // Password reset fields
      forgotPasswordCode: {
        type: DataTypes.STRING(64),
        allowNull: true,
      },
      forgotPasswordCodeValidation: {
        type: DataTypes.BIGINT,
        allowNull: true,
      },
      lastForgotPasswordCodeSentAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      failedPasswordAttempts: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
        validate: {
          min: 0,
        },
      },
      lastFailedPasswordAttempt: {
        type: DataTypes.DATE,
        allowNull: true,
      },

      // Account status management
      status: {
        type: DataTypes.ENUM("active", "suspended", "deleted"),
        defaultValue: "active",
        allowNull: false,
        validate: {
          isIn: {
            args: [["active", "suspended", "deleted"]],
            msg: "Invalid account status",
          },
        },
      },

      // Last activity tracking
      lastLoginAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      lastActivityAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
    },
    {
      // Model options
      timestamps: true,
      paranoid: true, // Enables soft deletion
      underscored: true, // Uses snake_case for column names
      freezeTableName: true, // Prevents pluralization

      // Default scope excludes sensitive fields
      defaultScope: {
        attributes: {
          exclude: [
            "password",
            "verificationCode",
            "verificationCodeValidation",
            "forgotPasswordCode",
            "forgotPasswordCodeValidation",
          ],
        },
        where: {
          status: "active",
        },
      },

      // Custom scopes for different use cases
      scopes: {
        withPassword: {
          attributes: { include: ["password"] },
        },
        withVerification: {
          attributes: {
            include: [
              "verificationCode",
              "verificationCodeValidation",
              "lastVerificationCodeSentAt",
              "failedAttempts",
              "lastFailedAttempt",
            ],
          },
        },
        withPasswordReset: {
          attributes: {
            include: [
              "forgotPasswordCode",
              "forgotPasswordCodeValidation",
              "lastForgotPasswordCodeSentAt",
              "failedPasswordAttempts",
              "lastFailedPasswordAttempt",
            ],
          },
        },
        withSensitiveData: {
          attributes: { exclude: [] }, // Include all fields
        },
        active: {
          where: { status: "active" },
        },
        suspended: {
          where: { status: "suspended" },
        },
        deleted: {
          paranoid: false,
          where: { status: "deleted" },
        },
      },

      // Database indexes for performance
      indexes: [
        {
          unique: true,
          fields: ["email"],
          where: {
            status: "active",
          },
          name: "unique_active_email",
        },
        {
          fields: ["verified"],
          name: "user_verified_index",
        },
        {
          fields: ["status"],
          name: "user_status_index",
        },
        {
          fields: ["created_at"],
          name: "user_created_at_index",
        },
        {
          fields: ["last_activity_at"],
          name: "user_last_activity_index",
        },
      ],
    }
  );

  /* ==================== INSTANCE METHODS ==================== */

  /**
   * Verify a password against the stored hash
   * @param {string} candidatePassword - The password to verify
   * @returns {Promise<boolean>} - Whether the password matches
   */
  User.prototype.verifyPassword = async function (candidatePassword) {
    const { doHashValidation } = require("../utils/hashing");
    return doHashValidation(candidatePassword, this.password);
  };

  /**
   * Generate and store a verification code
   * @returns {string} - The plaintext verification code
   */
  User.prototype.generateVerificationCode = function () {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    this.verificationCode = hmacProcess(code, process.env.HMAC_SECRET);
    this.verificationCodeValidation = Date.now();
    this.lastVerificationCodeSentAt = new Date();
    return code;
  };

  /**
   * Generate and store a password reset code
   * @returns {string} - The plaintext reset code
   */
  User.prototype.generatePasswordResetCode = function () {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    this.forgotPasswordCode = hmacProcess(code, process.env.HMAC_SECRET);
    this.forgotPasswordCodeValidation = Date.now();
    this.lastForgotPasswordCodeSentAt = new Date();
    return code;
  };

  /**
   * Verify a provided code against stored hash
   * @param {string} code - The code to verify
   * @param {string} type - 'verification' or 'passwordReset'
   * @returns {boolean} - Whether the code is valid
   */
  User.prototype.verifyCode = function (code, type = "verification") {
    const hashedCode = hmacProcess(code, process.env.HMAC_SECRET);
    if (type === "verification") {
      return hashedCode === this.verificationCode;
    } else if (type === "passwordReset") {
      return hashedCode === this.forgotPasswordCode;
    }
    return false;
  };

  /**
   * Check if a code has expired
   * @param {string} type - 'verification' or 'passwordReset'
   * @param {number} [expiryMinutes=5] - Expiration time in minutes
   * @returns {boolean} - Whether the code has expired
   */
  User.prototype.isCodeExpired = function (
    type = "verification",
    expiryMinutes = 5
  ) {
    const validationTime =
      type === "verification"
        ? this.verificationCodeValidation
        : this.forgotPasswordCodeValidation;

    if (!validationTime) return true;

    return Date.now() - validationTime > expiryMinutes * 60 * 1000;
  };

  /* ==================== MODEL HOOKS ==================== */

  // Hash password before create and update
  User.beforeSave(async (user, options) => {
    if (user.changed("password")) {
      user.password = await doHash(user.password, 12);
    }
  });

  // Update last activity timestamp before update
  User.beforeUpdate(async (user, options) => {
    if (user.changed("lastActivityAt") === false) {
      user.lastActivityAt = new Date();
    }
  });

  // Clean up sensitive data when account is soft deleted
  User.beforeDestroy(async (user, options) => {
    await user.update(
      {
        password: crypto.randomBytes(32).toString("hex"), // Randomize password
        verificationCode: null,
        forgotPasswordCode: null,
        status: "deleted",
      },
      { transaction: options.transaction }
    );
  });

  /* ==================== STATIC METHODS ==================== */

  /**
   * Find a user by credentials (email + password)
   * @param {string} email - User email
   * @param {string} password - User password
   * @returns {Promise<User|null>} - Authenticated user or null
   */
  User.findByCredentials = async function (email, password) {
    const user = await this.scope("withPassword").findOne({
      where: { email: email.toLowerCase().trim() },
    });

    if (!user) return null;

    const isMatch = await user.verifyPassword(password);
    return isMatch ? user : null;
  };

  /**
   * Find a user by email with verification data
   * @param {string} email - User email
   * @returns {Promise<User|null>} - User with verification data or null
   */
  User.findForVerification = async function (email) {
    return await this.scope("withVerification").findOne({
      where: { email: email.toLowerCase().trim() },
    });
  };

  /**
   * Find a user by email with password reset data
   * @param {string} email - User email
   * @returns {Promise<User|null>} - User with reset data or null
   */
  User.findForPasswordReset = async function (email) {
    return await this.scope("withPasswordReset").findOne({
      where: { email: email.toLowerCase().trim() },
    });
  };

  return User;
};
