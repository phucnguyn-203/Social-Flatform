const mongoose = require("mongoose");
const { Schema } = mongoose;
const bcrypt = require("bcrypt");

const userSchema = new Schema({
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
});

userSchema.pre("save", async function (next) {
    if (this.isModified("password")) {
        this.password = await bcrypt.hash(this.password, 12);
        this.passwordConfirm = undefined;
    }
    next();
});

userSchema.methods.correctPassword = async function (password, userPassword) {
    return await bcrypt.compare(password, userPassword);
};

const User = mongoose.model("User", userSchema);
module.exports = User;
