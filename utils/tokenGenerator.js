const crypto = require("crypto");
const { getSecretFromDB } = require("./mockDb");

const generateToken = async (email) => {
  try {
    const secret = await getSecretFromDB();

    // Generate a random salt (16 bytes → 32 hex chars)
    const salt = crypto.randomBytes(16).toString("hex");

    return crypto
      .createHmac("sha256", secret) // secure algorithm
      .update(email + Date.now().toString() + salt) // add salt for unpredictability
      .digest("hex");
  } catch (error) {
    console.error("Token Generation Error:", error.message);
    throw error;
  }
};

module.exports = { generateToken };