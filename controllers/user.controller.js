const User = require("../models/user.model");
const sendEmail = require("../utils/email");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const signAccessToken = (_id, role) => {
    return jwt.sign({ _id, role }, process.env.ACCESS_TOKEN_SECRET_KEY, {
        expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN,
    });
};

const signRefreshToken = (_id, role) => {
    return jwt.sign({ _id, role }, process.env.REFRESH_TOKEN_SECRET_KEY, {
        expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN,
    });
};

const sendToken = (res, { name, token, maxAge }) => {
    cookieOptions = {
        httpOnly: true,
        sameSite: "strict",
    };

    res.cookie(name, token, { ...cookieOptions, maxAge });
};

exports.signUp = async (req, res) => {
    try {
        const newUser = await User.create({
            email: req.body.email,
            username: req.body.username,
            password: req.body.password,
            passwordConfirm: req.body.passwordConfirm,
        });
        newUser.password = undefined;
        res.status(201).json({
            status: "success",
            data: {
                user: newUser,
            },
        });
    } catch (err) {
        res.status(500).json({
            status: "fail",
            data: err,
        });
    }
};

exports.signIn = async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({
            status: "fail",
            message: "Vui lòng nhập username và password",
        });
    }
    const user = await User.findOne({ username }).select("+password");
    if (!user || !(await user.correctPassword(password, user.password))) {
        return res.status(401).json({
            status: "fail",
            message:
                "Đăng nhập không thành công Email hoặc mật khẩu không đúng",
        });
    }

    sendToken(res, {
        name: "accessToken",
        token: signAccessToken(user._id, user.role),
        maxAge: 24 * 60 * 60 * 1000,
    });
    sendToken(res, {
        name: "refreshToken",
        token: signRefreshToken(user._id, user.role),
        maxAge: 90 * 24 * 60 * 60 * 1000,
    });
    user.password = undefined;
    res.status(200).json({
        status: "success",
        data: user,
    });
};

exports.forgotPassword = async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({
            status: "fail",
            message: "Vui lòng điền Email của bạn",
        });
    }

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(404).json({
            status: "fail",
            message: "Email không tồn tại",
        });
    }

    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    let resetURL = `${req.protocol}://${req.get(
        "host"
    )}/api/v1/users/reset-password/${resetToken}`;
    const message = `Mật khẩu của bạn có thể được đặt lại bằng click vào đường dẫn này: ${resetURL} .Đường dẫn sẽ có hiệu lực trong 10 phút. Nếu bạn không yêu cầu đặt lại mật khẩu vui lòng bỏ qua email này`;
    try {
        await sendEmail({
            to: email,
            subject: "Đặt lại mật khẩu của bạn(hiệu lực trong 10 phút)",
            message,
        });
        res.status(200).json({
            status: "success",
            message:
                "Một email đặt lại mật khẩu đã được gửi tới địa chỉ email của bạn",
        });
    } catch (err) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });
        return res.status(500).json({
            status: "fail",
            message: "Xảy ra lỗi trong quá trình gửi email. Hãy thử lại sau",
        });
    }
};

exports.resetPassword = async (req, res) => {
    const hashedToken = crypto
        .createHash("sha256")
        .update(req.params.token)
        .digest("hex");
    const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: Date.now() },
    });
    if (!user) {
        return res.status(400).json({
            status: "fail",
            message: "Đường dẫn không hợp lệ hoặc đã hết hạn",
        });
    }
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    res.status(200).json({
        status: "success",
        message: "Mật khẩu được cập nhật thành công",
    });
};
