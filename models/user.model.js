const mongoose = require("mongoose");
const { Schema } = mongoose;
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const userSchema = new Schema({
    email: {
        type: String,
        required: [true, "Vui lòng nhập email của bạn"],
        unique: true,
    },
    username: {
        type: String,
        unique: true,
        required: [true, "Vui lòng nhập tên đăng nhập"],
    },
    password: {
        type: String,
        required: true,
        minLength: [8, "Độ dài mật khẩu nên lớn hơn hoặc bằng 8 kí tự"],
        select: false,
    },
    passwordConfirm: {
        type: String,
        required: [true, "Vui lòng nhập lại mật khẩu."],
        validate: {
            validator: function (val) {
                return val === this.password;
            },
            message: "Mật khẩu xác nhận không khớp.",
        },
    },
    passwordChangeAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
});

userSchema.pre("save", async function (next) {
    if (this.isModified("password")) {
        this.password = await bcrypt.hash(this.password, 12);
        this.passwordConfirm = undefined;
    }
    next();
});

userSchema.pre("save", function (next) {
    if (this.isModified("password") && !this.isNew) {
        this.passwordChangeAt = Date.now();
    }
    next();
});

userSchema.methods.changePasswordAfter = function (JWTTimestamps) {
    if (this.passwordChangeAt) {
        const changedTimestamp = this.passwordChangeAt.getTime() / 1000;
        return JWTTimestamps < changedTimestamp;
    }
    return false;
};

userSchema.methods.createPasswordResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString("hex");
    this.passwordResetToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");
    this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
    return resetToken;
};

userSchema.methods.correctPassword = async function (password, userPassword) {
    return await bcrypt.compare(password, userPassword);
};

const User = mongoose.model("User", userSchema);
module.exports = User;
