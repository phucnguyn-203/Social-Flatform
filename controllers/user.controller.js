const User = require("../models/user.model");
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
