const { User, Buyer, Seller, DeliveryPerson, Admin } = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const e = require("../utils/error");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

module.exports = {
    // 🔹 SIGNUP (Only for buyers)
    signup: async (req, res, next) => {
        try {
            const { name, email, password, confirmPassword, address, phoneNumber } = req.body;

            // Check if email already exists
            if (await User.findOne({ email })) {
                return next(e.errorHandler(400, "Email already in use"));
            }

            // Check if passwords match
            if (password !== confirmPassword) {
                return next(e.errorHandler(400, "Passwords do not match"));
            }

            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Create a new buyer
            const newBuyer = new Buyer({
                name,
                email,
                password: hashedPassword,
                role: "buyer", // Explicitly set role to "buyer"
                address: address || "Not provided", // Default value for address
                phoneNumber: phoneNumber || "Not provided", // Default value for phoneNumber
            });

            await newBuyer.save();
            res.status(201).json({ message: "Buyer registered successfully", user: newBuyer });
        } catch (error) {
            next(error);
        }
    },

    // 🔹 SIGNIN (For all users)
    signin: async (req, res, next) => {
        try {
            const { email, password } = req.body;

            // Check if the user exists
            const user = await User.findOne({ email });
            if (!user) return next(e.errorHandler(400, "Invalid email or password"));

            // Check if the password is correct
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return next(e.errorHandler(400, "Invalid email or password"));

            // Check if the account is active
            if (!user.isActive) {
                return next(e.errorHandler(403, "Your account has been deactivated"));
            }

            // Generate JWT token
            const token = jwt.sign(
                { userId: user._id, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: "7d" }
            );

            // Send the token in a secure cookie
            res.cookie("access_token", token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            });

            // Send response with user data (excluding password)
            const { password: _, ...userData } = user._doc;
            res.status(200).json({
                message: "Signin successful",
                user: userData,
            });
        } catch (error) {
            next(error);
        }
    },

    // 🔹 GOOGLE AUTH (Only for buyers)
    google: async (req, res, next) => {
        const { email, name, googlePhotoUrl } = req.body;

        try {
            // Check if the user already exists
            const user = await User.findOne({ email });
            if (user) {
                // Ensure the user is a buyer
                if (user.role !== "buyer") {
                    return next(e.errorHandler(403, "Google authentication is only available for buyers."));
                }

                // Generate JWT token
                const token = jwt.sign(
                    { userId: user._id, role: user.role },
                    process.env.JWT_SECRET,
                    { expiresIn: "7d" }
                );

                // Remove password from the user object
                const { password, ...rest } = user._doc;

                // Send response with token and user data
                res
                    .status(200)
                    .cookie("access_token", token, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === "production",
                        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
                    })
                    .json(rest);
            } else {
                // Generate a random password
                const generatedPassword =
                    Math.random().toString(36).slice(-8) +
                    Math.random().toString(36).slice(-8);
                const hashedPassword = bcrypt.hashSync(generatedPassword, 10);

                // Create a new buyer with default values
                const newUser = new Buyer({
                    name: name || "Google User",
                    email,
                    password: hashedPassword,
                    profilePicture: googlePhotoUrl || 'https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_960_720.png',
                    role: "buyer", // Force the role to be "buyer"
                    isActive: true,
                    address: "Not provided", // Default value for address
                    phoneNumber: "Not provided", // Default value for phoneNumber
                });

                await newUser.save();

                // Generate JWT token for the new user
                const token = jwt.sign(
                    { userId: newUser._id, role: newUser.role },
                    process.env.JWT_SECRET,
                    { expiresIn: "7d" }
                );

                // Remove password from the user object
                const { password, ...rest } = newUser._doc;

                // Send response with token and user data
                res
                    .status(200)
                    .cookie("access_token", token, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === "production",
                        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
                    })
                    .json(rest);
            }
        } catch (error) {
            next(error);
        }
    },

    // 🔹 FORGOT PASSWORD (For all users)
    forgotPassword: async (req, res, next) => {
        try {
            const { email } = req.body;

            // Check if the user exists
            const user = await User.findOne({ email });
            if (!user) {
                return next(e.errorHandler(404, "User not found"));
            }

            // Generate a reset token
            const resetToken = crypto.randomBytes(20).toString("hex");
            const resetPasswordToken = crypto
                .createHash("sha256")
                .update(resetToken)
                .digest("hex");

            // Set token expiration (e.g., 1 hour)
            const resetPasswordExpires = Date.now() + 3600000; // 1 hour

            // Save the token and expiration in the database
            user.resetPasswordToken = resetPasswordToken;
            user.resetPasswordExpires = resetPasswordExpires;
            await user.save();

            // Send email with reset link
            const resetUrl = `http://localhost:5173/reset-password/${resetToken}`;
            const mailOptions = {
                to: user.email,
                from: process.env.EMAIL_USER,
                subject: "Password Reset",
                text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
                Please click on the following link, or paste this into your browser to complete the process:\n\n
                ${resetUrl}\n\n
                If you did not request this, please ignore this email and your password will remain unchanged.\n`,
            };

            await transporter.sendMail(mailOptions);

            res.status(200).json({ message: "Password reset email sent" });
        } catch (error) {
            next(error);
        }
    },

    // 🔹 RESET PASSWORD (For all users)
    resetPassword: async (req, res, next) => {
        try {
            const { token } = req.params;
            const { password } = req.body;

            // Hash the token to compare with the one in the database
            const resetPasswordToken = crypto
                .createHash("sha256")
                .update(token)
                .digest("hex");

            // Find the user with the matching token and check if it's still valid
            const user = await User.findOne({
                resetPasswordToken,
                resetPasswordExpires: { $gt: Date.now() },
            });

            if (!user) {
                return next(e.errorHandler(400, "Invalid or expired token"));
            }

            // Hash the new password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Update the user's password and clear the reset token
            user.password = hashedPassword;
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;
            await user.save();

            res.status(200).json({ message: "Password reset successful" });
        } catch (error) {
            next(error);
        }
    },
};