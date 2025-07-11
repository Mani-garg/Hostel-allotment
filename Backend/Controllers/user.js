import nodemailer from "nodemailer";
import User from "../Models/user.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import RecentActivity from "../Models/RecentActivity.js";

// Use environment variable instead of hardcoding
const secret = process.env.JWT_SECRET || "rajbirsingh1234";

// ✅ Generate 6-digit OTP
const generateOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

// ✅ USER SIGNUP
export async function handleUserSignUp(req, res) {
  try {
    const { name, email, password, address, dob, phoneNumber, enrollmentId } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "Email already in use" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      address,
      phoneNumber,
      password: hashedPassword,
      dob,
      enrollmentId,
    });

    const userResponse = {
      name: user.name,
      email: user.email,
      address: user.address,
      dob: user.dob,
      phoneNumber: user.phoneNumber,
      role: user.role,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };

    return res.status(201).json(userResponse);
  } catch (error) {
    console.log("Signup Error:", error.message);
    return res.status(500).json({ message: "Server error" });
  }
}

// ✅ USER LOGIN
export async function handleUserLogin(req, res) {
  const { email, password } = req.body;
  console.log("Login attempt:", email, password);

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const data = { user: { id: user.id, enrollmentId: user.enrollmentId } };
    const authToken = jwt.sign(data, secret);

    res.cookie("token", authToken, {
      httpOnly: true,
      sameSite: "lax",
    });

    return res.status(200).json({ authToken, id: user._id, role: user.role });
  } catch (error) {
    console.error("Login Error:", error.message);
    return res.status(500).json({ message: "Internal server error" });
  }
}

// ✅ USER LOGOUT
export async function handleUserLogout(req, res) {
  try {
    res.clearCookie("token");
    return res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error.message);
    return res.status(500).send("Internal server error");
  }
}

// ✅ FETCH USER DATA
export async function fetchUserData(req, res) {
  try {
    const studentId = req.params.id;
    if (!studentId) return res.status(400).json({ message: "Student ID required" });

    const student = await User.findById(studentId);
    if (!student) return res.status(404).json({ message: "User not found" });

    return res.status(200).json(student);
  } catch (error) {
    console.error("Fetch user error:", error.message);
    return res.status(500).json({ message: "Server error" });
  }
}

// ✅ SEND OTP
export const handleSendOtp = async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email is required" });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const otp = generateOTP();
    user.otp = otp;
    user.expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    await user.save();

    const transporter = nodemailer.createTransport({
      service: "gmail",
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: "ggbackup8520@gmail.com",
        pass: "swpj cbea mdni rbdv",
      },
    });

    const mailOptions = {
      from: "ggbackup8520@gmail.com",
      to: email,
      subject: "Your OTP for Password Reset",
      text: `Your OTP is ${otp}. It is valid for 10 minutes.`,
    };

    await transporter.sendMail(mailOptions);
    return res.status(200).json({ message: "OTP sent to email" });
  } catch (error) {
    console.error("OTP send error:", error.message);
    return res.status(500).json({ message: "Failed to send OTP" });
  }
};

// ✅ VERIFY OTP AND RESET PASSWORD
export const handleVerifyOtp = async (req, res) => {
  const { email, verifyOtp, newPassword } = req.body;

  if (!email || !verifyOtp || !newPassword)
    return res.status(400).json({ message: "All fields required" });

  try {
    const user = await User.findOne({ email });
    if (!user || !user.otp || !user.expiresAt)
      return res.status(400).json({ message: "OTP not found or expired" });

    if (Date.now() > user.expiresAt) {
      user.otp = null;
      user.expiresAt = null;
      await user.save();
      return res.status(400).json({ message: "OTP expired" });
    }

    if (verifyOtp !== user.otp)
      return res.status(400).json({ message: "Incorrect OTP" });

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = null;
    user.expiresAt = null;

    await user.save();
    return res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    console.error("Verify OTP error:", error.message);
    return res.status(500).json({ message: "Failed to verify OTP" });
  }
};

// ✅ USER PROFILE UPDATE
export const userEdit = async (req, res) => {
  const { _id, fullName, email, mobile } = req.body;
  if (!_id) return res.status(400).json({ error: "User ID required" });

  try {
    const updatedUser = await User.findByIdAndUpdate(
      _id,
      { fullName, email, mobile },
      { new: true }
    );

    if (!updatedUser)
      return res.status(404).json({ error: "User not found" });

    return res.status(200).json({ user: updatedUser });
  } catch (error) {
    console.error("User update error:", error.message);
    return res.status(500).json({ error: "Server error" });
  }
};

// ✅ FETCH RECENT ACTIVITY
export const handleFetchRecentActivity = async (req, res) => {
  try {
    const user = req.user;
    const activities = await RecentActivity.find({
      enrollmentId: user.enrollmentId,
    }).sort({ createdAt: -1 });

    return res.status(200).json(activities);
  } catch (error) {
    console.error("Fetch activity error:", error.message);
    return res.status(500).json({ error: "Failed to fetch activities" });
  }
};
