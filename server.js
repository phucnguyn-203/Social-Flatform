const express = require("express");
const app = express();
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
dotenv.config();

const DB = process.env.DB_HOST.replace("<password>", process.env.DB_PASSWORD);
mongoose
    .connect(DB)
    .then(() => {
        console.log("Database connection successful");
    })
    .catch((err) => console.log(err));

const userRouter = require("./routes/user.route");

//COOKIE PARSER
app.use(cookieParser());

//BODY PARSER
app.use(express.json({ limit: "50mb" }));

app.use("/api/v1/user", userRouter);

const port = process.env.PORT || 8080;
app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});
