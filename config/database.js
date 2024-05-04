const mongoose = require("mongoose");

require('dotenv').config();

exports.connect = () =>{
    mongoose.connect(process.env.MONGODB_URL)
    .then(()=>{
        console.log("MongoDB connected successfully");
    })
    .catch((err)=>{
        console.log("DB connection issues");
        console.error(err);
        process.exit(1);
    })
}