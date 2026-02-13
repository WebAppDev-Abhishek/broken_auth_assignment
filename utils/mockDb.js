const getSecretFromDB = async () => {
  // Simulates a database delay
  await new Promise((resolve) => setTimeout(resolve, 120));

  const secret = process.env.APPLICATION_SECRET;
  if (!secret) {
    throw new Error("Missing APPLICATION_SECRET in environment variables");
  }

  return secret;
};

module.exports = { getSecretFromDB };