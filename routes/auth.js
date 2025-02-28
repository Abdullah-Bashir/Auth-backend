import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import validator from "validator";
import User from "../schema/user.js";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import { authMiddleware } from "../middleware/auth.js";

dotenv.config(); // Load environment variables

const router = express.Router();

const validatePassword = (password) => {
    if (password.length < 8) {
        throw new Error("Password must be at least 8 characters long");
    }
    if (!/[A-Z]/.test(password)) {
        throw new Error("Password must contain at least one uppercase letter");
    }
    if (!/[a-z]/.test(password)) {
        throw new Error("Password must contain at least one lowercase letter");
    }
    if (!/[0-9]/.test(password)) {
        throw new Error("Password must contain at least one number");
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
        throw new Error("Password must contain at least one special character");
    }
};

// Initialize Nodemailer transporter
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true, // Use SSL/TLS
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    tls: {
        rejectUnauthorized: false, // Do not fail on invalid certificates
    },
    debug: true, // Enable debugging
    logger: true, // Log to console
});

// Verify transporter configuration
transporter.verify((error, success) => {
    if (error) {
        console.error("SMTP configuration error:", error);
    } else {
        console.log("SMTP server is ready to send emails");
    }
});

// Helper function to send email
const sendEmail = async (to, subject, html) => {
    try {
        const info = await transporter.sendMail({
            from: `"Your Company Name" <${process.env.EMAIL_USER}>`,
            to,
            subject,
            html,
        });
        console.log("Message sent: %s", info.messageId);
    } catch (error) {
        console.error("Error sending email:", error);
        throw new Error("Failed to send email");
    }
};

// Helper function to generate JWT token
const generateToken = (user) => {
    return jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
};

// Register route
router.post("/register", async (req, res, next) => {
    try {
        const { username, email, password, phone } = req.body;

        if (!username || !email || !password || !phone) {
            return res.status(400).json({ message: "All fields are required" });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ message: "Invalid email format" });
        }

        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            if (existingEmail.accountVerified) {
                return res.status(400).json({ message: "Email already exists and is verified" });
            } else {
                return res.status(400).json({
                    message: "Email exists but is not verified. Please verify your account or use a different email.",
                });
            }
        }

        const existingPhone = await User.findOne({ phone });
        if (existingPhone) {
            if (existingPhone.accountVerified) {
                return res.status(400).json({ message: "Phone number already exists and is verified" });
            } else {
                return res.status(400).json({
                    message:
                        "Phone number exists but is not verified. Please verify your account or use a different phone number.",
                });
            }
        }

        const registrationAttempts = await User.countDocuments({
            $or: [{ email }, { phone }],
            createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
        });

        if (registrationAttempts >= 3) {
            return res.status(400).json({ message: "Maximum registration attempts reached. Please try again later." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationCode = Math.floor(100000 + Math.random() * 900000);
        const verificationCodeExpire = new Date(Date.now() + 10 * 60 * 1000); // Expires in 10 minutes

        const user = new User({
            username,
            password: hashedPassword,
            email,
            phone,
            verificationCode,
            verificationCodeExpire,
        });

        await user.save();

        try {
            const htmlTemplate = `
                <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
                    <h2 style="color: #4CAF50; text-align: center;">Welcome to Our Service!</h2>
                    <p>Hello,</p>
                    <p>Thank you for registering with us. To complete your registration, please use the verification code below:</p>
                    <div style="background: #f4f4f4; padding: 10px; text-align: center; border-radius: 4px; margin: 20px 0;">
                        <h1 style="margin: 0; font-size: 32px; color: #4CAF50;">${verificationCode}</h1>
                    </div>
                    <p>This code will expire at <strong>${verificationCodeExpire.toLocaleString("en-US", {
                hour: "numeric",
                minute: "numeric",
                hour12: true,
            })}</strong>. If you did not request this code, please ignore this email.</p>
                    <p>Best regards,</p>
                    <p><strong>Your Company Name</strong></p>
                    <p style="text-align: center; margin-top: 20px;">
                        <a href="https://yourwebsite.com" style="color: #4CAF50; text-decoration: none;">Visit Our Website</a>
                    </p>
                </div>
            `;

            await sendEmail(email, "Your Verification Code", htmlTemplate);

        } catch (error) {
            console.error("Error sending verification code:", error);
            await User.deleteOne({ _id: user._id });
            return res.status(500).json({ message: "Error sending verification code. Please try again." });
        }

        res.status(201).json({
            message: "User registered successfully. Please check your email for the verification code.",
        });
    } catch (error) {
        next(error);
    }
});

// Verify route
router.post("/verify", async (req, res, next) => {
    try {
        const { email, verificationCode } = req.body;

        // Validate input
        if (!email || !verificationCode) {
            return res.status(400).json({ message: "Email and verification code are required" });
        }

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Check if already verified
        if (user.accountVerified) {
            return res.status(400).json({ message: "Account is already verified" });
        }

        // Validate verification code
        if (user.verificationCode !== Number.parseInt(verificationCode)) {
            return res.status(400).json({ message: "Invalid verification code" });
        }

        // Check if code is expired
        if (user.verificationCodeExpire < new Date()) {
            return res.status(400).json({ message: "Verification code has expired" });
        }

        // Mark account as verified and clear verification code
        user.accountVerified = true;
        user.verificationCode = undefined;
        user.verificationCodeExpire = undefined;
        await user.save();

        // Generate token
        // const token = generateToken(user);

        // Send token as a cookie
        // res.cookie("token", token, {
        //     httpOnly: true, // Prevent client-side JavaScript from accessing the cookie
        //     secure: process.env.NODE_ENV === "production", // Send cookie only over HTTPS in production
        //     maxAge: 3600000, // Cookie expires in 1 hour (in milliseconds)
        //     sameSite: "strict", // Prevent CSRF attacks
        // });

        // Send success response
        res.status(200).json({ message: "Account verified successfully" });
    } catch (error) {
        next(error);
    }
});

// Login rout
router.post("/login", async (req, res, next) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required" });
        }

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        // Validate password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        // Check if account is verified
        if (!user.accountVerified) {
            return res.status(401).json({ message: "Please verify your account" });
        }

        // Generate token
        const token = generateToken(user);

        // Send token as a cookie
        res.cookie("auth_token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 3600000,
            sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
        });

        // Send success response
        res.status(200).json({ message: "Logged in successfully" });
    } catch (error) {
        next(error);
    }
});

// Forgot password route
router.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;

        // Check if email is provided
        if (!email) {
            return res.status(400).json({ message: "Email is required" });
        }

        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Generate reset token
        const resetToken = crypto.randomBytes(20).toString("hex");

        // Hash the token and save it in the database
        user.resetPasswordToken = crypto.createHash("sha256").update(resetToken).digest("hex");
        user.resetPasswordExpire = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
        await user.save();

        // Generate reset URL
        const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

        // Send email with reset link
        const htmlTemplate = `
            <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
                <h2 style="color:rgb(18, 207, 24); text-align: center;">Password Reset Request</h2>
                <p>Hello,</p>
                <p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
                <p>Please click on the following link, or paste it into your browser to complete the process:</p>
                <div style="background: #f4f4f4; padding: 10px; text-align: center; border-radius: 4px; margin: 20px 0;">
                    <a href="${resetUrl}" style="color:rgb(16, 184, 21); text-decoration: none;">Reset Password</a>
                </div>
                <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
                <p>Best regards,</p>
                <p><strong>Your Company Name</strong></p>
            </div>
        `;

        await transporter.sendMail({
            from: `"Your Company Name" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "Password Reset Request",
            html: htmlTemplate,
        });

        res.json({ message: "Password reset email sent" });
    } catch (error) {
        console.error("Error in forgot password:", error);
        res.status(500).json({ message: "An error occurred. Please try again." });
    }
});

// reset password
router.put("/reset-password/:token", async (req, res) => {
    try {
        const { token: resetToken } = req.params; // Rename `token` to `resetToken`
        const { newPassword, confirmPassword } = req.body;

        // Validate input
        if (!newPassword || !confirmPassword) {
            return res.status(400).json({ message: "Both password fields are required" });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: "Passwords do not match" });
        }

        // Validate password strength
        validatePassword(newPassword);

        // Hash the token for comparison
        const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex"); // Use `resetToken`

        // Find user with valid token
        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpire: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: "Invalid or expired token" });
        }

        // Update password and clear reset fields
        user.password = await bcrypt.hash(newPassword, 10);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;
        await user.save();

        // Generate a new JWT
        const jwtToken = generateToken(user); // Use `jwtToken` instead of `token`

        // Set JWT in a cookie
        res.cookie("token", jwtToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 3600000, // 1 hour
            sameSite: "strict",
        });

        // Send success response
        res.json({ message: "Password reset successfully" });
    } catch (error) {

        res.status(500).json({ message: error.message || "An error occurred. Please try again." });
    }
});

router.get('/validate-token', authMiddleware, (req, res) => {
    // If authMiddleware passes, the token is valid
    res.json({
        valid: true,
        user: {
            id: req.user._id,
            email: req.user.email,
            role: req.user.role // Add any other user details you need
        }
    });
});

router.post('/logout', (req, res) => {
    res.clearCookie('auth_token'); // Clear the cookie
    res.json({ message: 'Logged out successfully' });
});

export default router;