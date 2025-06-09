const { createHmac } = require("crypto");
const { hash, compare } = require("bcryptjs");

exports.doHash = async (value, saltValue = 12) => {
  try {
    if (!value) throw new Error("No value provided for hashing");
    return await hash(value, saltValue);
  } catch (error) {
    console.error("Hashing error:", error);
    throw error; // Re-throw for controller to handle
  }
};

exports.doHashValidation = async (plainValue, hashedValue) => {
  try {
    if (!plainValue || !hashedValue) {
      throw new Error("Both values are required for comparison");
    }
    return await compare(plainValue, hashedValue);
  } catch (error) {
    console.error("Hash validation error:", error);
    throw error;
  }
};

exports.hmacProcess = (value, key) => {
  try {
    if (!value || !key) throw new Error("Value and key are required for HMAC");
    return createHmac("sha256", key)
      .update(value.toString()) // Ensure string input
      .digest("hex");
  } catch (error) {
    console.error("HMAC processing error:", error);
    throw error;
  }
};
