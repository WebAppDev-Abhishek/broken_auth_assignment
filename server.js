require('dotenv').config(); // Load environment variables
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto"); // For secure session IDs
const bcrypt = require("bcrypt"); // For secure password handling
const requestLogger = require("./middleware/logger");
const authMiddleware = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 3000;

// Memory storage for demo (In production, use Redis or a Database)
const loginSessions = {};
const otpStore = {};

// Middleware
app.use(requestLogger);
app.use(express.json());
app.use(cookieParser());

// Root Route
app.get("/", (req, res) => {
  res.json({
    challenge: "Authentication Assignment",
    status: "Ready for secure login flow.",
  });
});

// 1. LOGIN: Generate Session and OTP
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    // FIX: Use cryptographically secure session IDs
    const loginSessionId = crypto.randomBytes(16).toString('hex');
    const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP

    // FIX: Hash the password before storing in memory to prevent plain-text theft
    const hashedPassword = await bcrypt.hash(password, 10);

    loginSessions[loginSessionId] = {
      email,
      password: hashedPassword,
      expiresAt: Date.now() + 5 * 60 * 1000, // Increased to 5 minutes
    };

    // Store OTP with an attempt counter to prevent brute-force
    otpStore[loginSessionId] = {
      code: otp,
      attempts: 0
    };

    console.log(`[SECURE OTP] Session ${loginSessionId} generated. OTP: ${otp}`);

    return res.status(200).json({
      message: "OTP generated successfully",
      loginSessionId,
    });
  } catch (error) {
    return res.status(500).json({ status: "error", message: "Login failed" });
  }
});

// 2. VERIFY OTP: Secure against guessing
app.post("/auth/verify-otp", (req, res) => {
  try {
    const { loginSessionId, otp } = req.body;
    const session = loginSessions[loginSessionId];
    const otpData = otpStore[loginSessionId];

    if (!session || Date.now() > session.expiresAt) {
      return res.status(401).json({ error: "Session invalid or expired" });
    }

    // FIX: Brute-Force Protection
    if (otpData.attempts >= 3) {
      delete loginSessions[loginSessionId];
      delete otpStore[loginSessionId];
      return res.status(403).json({ error: "Too many failed attempts. Session locked." });
    }

    if (parseInt(otp) !== otpData.code) {
      otpData.attempts++;
      return res.status(401).json({ error: `Invalid OTP. Attempts left: ${3 - otpData.attempts}` });
    }

    // On Success: Set a secure cookie
    res.cookie("session_verified", loginSessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    delete otpStore[loginSessionId]; // Clean up OTP after success

    return res.status(200).json({
      message: "OTP verified. You may now request an access token.",
      sessionId: loginSessionId,
    });
  } catch (error) {
    return res.status(500).json({ status: "error", message: "Verification failed" });
  }
});

// 3. TOKEN: Exchange Session for JWT
app.post("/auth/token", (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "No session ID provided" });

    const sessionId = authHeader.replace("Bearer ", "");
    const session = loginSessions[sessionId];

    if (!session) {
      return res.status(401).json({ error: "Invalid or unauthorized session" });
    }

    // FIX: Force use of environment variable secret
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        return res.status(500).json({ error: "Server configuration error: JWT_SECRET missing" });
    }

    const accessToken = jwt.sign(
      { email: session.email, sid: sessionId },
      secret,
      { expiresIn: "15m" }
    );

    return res.status(200).json({
      access_token: accessToken,
      expires_in: 900,
    });
  } catch (error) {
    return res.status(500).json({ status: "error", message: "Token generation failed" });
  }
});

// 4. PROTECTED ROUTE: Final Challenge
app.get("/protected", authMiddleware, (req, res) => {
  return res.json({
    message: "Success! You have bypassed the broken authentication.",
    user: req.user,
    flag: `FLAG-${Buffer.from(req.user.email + "_SECURE_AUTH_COMPLETE").toString('base64')}`,
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});