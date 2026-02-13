const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: Access Denied" });
  }

  const token = authHeader.split(" ")[1];

  try {
    // Uses the secret from .env exclusively
    const secret = process.env.JWT_SECRET;
    if (!secret) throw new Error("Server Error: Missing JWT Secret");

    const decoded = jwt.verify(token, secret);
    req.user = decoded; // Attach user info to request
    
    next(); // CRITICAL: Move to the protected route
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};