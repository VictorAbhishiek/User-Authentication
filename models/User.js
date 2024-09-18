const mongoose = require('mongoose');

// Connect to the MongoDB database at the specified URI
mongoose.connect('mongodb://127.0.0.1:27017/loginform');
// Define a schema for the 'user' collection
const userSchema = mongoose.Schema({
    // Field for the username of the user
    username: String,
    // Field for the email address of the user
    email: String,
     // Field for the password of the user (hashed password)
    password: String,
});

// Create and export a Mongoose model based on the user schema
// The model name is 'user', and it will be associated with the 'users' collection in MongoDB
module.exports = mongoose.model("user", userSchema);