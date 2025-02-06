import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import transporter from "../config/nodemailer.js";

export const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: "All fields are required", success: false });
    }

    try {
        const existingUser = await userModel.findOne({ email });

        if (existingUser) {
            return res.status(400).json({ message: "Email already exists", success: false });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        // Sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Welcome to My Website",
            text: `Welcome to my Website! Your account has been created with the email: ${email}`,
        };

        await transporter.sendMail(mailOptions);

        return res.json({ message: "Registration successful", success: true });
    } catch (error) {
        return res.status(500).json({ message: error.message, success: false });
    }
};

export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "All fields are required", success: false });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: "User does not exist", success: false });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials", success: false });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return res.json({ message: "Login successful", success: true });
    } catch (error) {
        return res.status(500).json({ message: error.message, success: false });
    }
};

export const logout = async (req, res) => {
    try {
        res.clearCookie("token", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
        });

        return res.json({ message: "Logged out successfully", success: true });
    } catch (error) {
        return res.status(500).json({ message: error.message, success: false });
    }
};

export const sendVerifyOtp = async (req, res) => {
    try {
        const { userId } = req.body;
        const user = await userModel.findById(userId);

        if (!user) {
            return res.status(400).json({ message: "User not found", success: false });
        }

        if (user.isAccountVerified) {
            return res.status(400).json({ message: "Account already verified", success: false });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000)); // 6-digit OTP

        user.verifyOtp = otp;
        user.verifyOtpExpiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes expiry

        await user.save();

        // Send OTP email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Verify Your Account",
            text: `Your verification code is: ${otp}. Please verify your account using this OTP.`,
        };

        await transporter.sendMail(mailOptions);

        return res.json({ message: "Verification code sent successfully", success: true });
    } catch (error) {
        return res.status(500).json({ message: error.message, success: false });
    }
};

export const verifyEmail = async (req, res) => {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
        return res.status(400).json({ message: "All fields are required", success: false });
    }

    try {
        const user = await userModel.findById(userId);

        if (!user) {
            return res.status(400).json({ message: "User not found", success: false });
        }

        if (user.verifyOtp !== String(otp)) {
            return res.status(400).json({ message: "Invalid OTP", success: false });
        }

        if (user.verifyOtpExpiresAt < Date.now()) {
            return res.status(400).json({ message: "OTP expired", success: false });
        }

        user.isAccountVerified = true;
        user.verifyOtp = "";
        user.verifyOtpExpiresAt = 0;

        await user.save();
        return res.json({ message: "Email verified successfully", success: true });
    } catch (error) {
        return res.status(500).json({ message: error.message, success: false });
    }
};

