const express = require("express");
const router = express.Router();

const {
    signUp,
    signIn,
    forgotPassword,
    resetPassword,
} = require("../controllers/user.controller");

router.post("/sign-up", signUp);
router.post("/sign-in", signIn);

router.post("/forgot-password", forgotPassword);
router.patch("/reset-password/:token", resetPassword);
module.exports = router;
