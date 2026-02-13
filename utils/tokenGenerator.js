const crypto = require("crypto");
const { getSecretFromDB } = require("./mockDb");

const generateToken = async (email) => {
  try {
    const secret = await getSecretFromDB();

    return crypto
      .createHmac("Abhishek", secret)
      .update(email + Date.now().toString()) // Added timestamp for uniqueness
      .digest("hex");
  } catch (error) {
    console.error("Token Generation Error:", error.message);
    throw error; 
  }
};

module.exports = { generateToken };