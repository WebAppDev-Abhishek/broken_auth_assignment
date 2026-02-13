# The Silent Server (Backend Debugging Assignment)

This API is intentionally broken. Your task is to debug it and complete the authentication flow.

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the server:
   ```bash
   npm start
   ```
   Server runs at: `http://localhost:3000`

## Assignment Objective

The goal is to fix the broken authentication endpoints so that a user can:
1.  **Login** to get a session ID and OTP.
2.  **Verify the OTP** to get a valid session cookie.
3.  **Exchange the Session** for a JWT Access Token.
4.  **Access Protected Routes** using the token.

You will need to use your browser's developer tools, network inspection, and server logs to debug.

---

## Tasks & Verification

### Task 1: Fix Login
**Endpoint:** `POST /auth/login`
The server should generate a session and log an OTP to the console.

**Test Command:**
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"<YOUR_EMAIL@example.com>","password":"password123"}'
```
**Expected Outcome:**
- Server logs the OTP (e.g., `[OTP] Session abc12345 generated`).
- Response contains `loginSessionId`.

### Task 2: Fix OTP Verification
**Endpoint:** `POST /auth/verify-otp`
The server fails to verify the OTP correctly. You need to find out why.
*Hint: Check data types and how cookies are set.*

**Test Command:**
(Replace `<loginSessionId>` and `<otp>` with values from Task 1)
```bash
curl -c cookies.txt -X POST http://localhost:3000/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"loginSessionId":"<loginSessionId>","otp":"<otp_from_logs>"}'
```
**Expected Outcome:**
- `cookies.txt` is created containing a session cookie.
- Response says "OTP verified".

### Task 3: Fix Token Generation
**Endpoint:** `POST /auth/token`
This endpoint is supposed to issue a JWT, but it has a bug in how it reads the session.

**Test Command:**
```bash
# Uses the cookie captured in Task 2
curl -b cookies.txt -X POST http://localhost:3000/auth/token
```
**Expected Outcome:**
- Response contains `{ "access_token": "..." }`.

### Task 4: Fix Protected Route Access
**Endpoint:** `GET /protected`
Ensure the middleware correctly validates the token.

**Test Command:**
```bash
# Replace <jwt> with the token from Task 3
curl -H "Authorization: Bearer <jwt>" http://localhost:3000/protected
```
**Expected Outcome:**
- Response: `{ "message": "Access granted", "user": ... }`

---


## Expected Output

After fixing the bugs, you should be able to run the following sequence successfully:

1.  **Login**: Receive a `loginSessionId` and see an OTP in the server logs.
2.  **Verify OTP**: Receive a session cookie (`session_token`).
3.  **Get Token**: Exchange the session cookie for a JWT (`access_token`).
4.  **Access Protected Route**: Use the JWT to get a 200 OK response with user details and a **unique Success Flag**.

**Important**: You must use **your own email address** when testing the login flow. The success flag is generated based on the email you use.




## Submission

To submit your assignment:

1.  Push your code to a **Public GitHub Repository**.
2.  Add a file named `output.txt` in your repository.
    *   This file must contain the terminal output of all 4 test commands (Login, Verify OTP, Get Token, Access Protected Route).
    *   Ensure the final command's output showing the `success_flag` is clearly visible in this file.
3.  Share the link to your repository.

_______________________________________________________________________________________________________________________

As per the assignment requirements:

Code: Fully debugged and pushed to this public repository.

output.txt: Located in the root directory, containing the full terminal log of the 4-step testing sequence,
including the final Success Flag.

<img width="1371" height="239" alt="Login Receive a loginSessionId and see an OTP in the server logs" src="https://github.com/user-attachments/assets/f3a7b32e-6cb6-4902-b438-c0b0f7c0b529" />

<img width="1376" height="299" alt="Verify the OTP to get a valid session cookie" src="https://github.com/user-attachments/assets/57bb1a4e-d9c4-4907-b5a6-e06f674bb8a5" />

<img width="1373" height="399" alt="Exchange the Session for a JWT Access Token" src="https://github.com/user-attachments/assets/0c776564-1953-461c-ba39-ec7c6eb5aec3" />

<img width="1377" height="474" alt="Access Protected Routes using the token" src="https://github.com/user-attachments/assets/77949794-75bd-4783-81ce-fa075e90a306" />



