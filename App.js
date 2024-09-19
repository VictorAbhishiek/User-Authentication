require('dotenv').config();    
const cookieParser = require('cookie-parser');
const express = require('express');
const userModel = require("./models/User");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";  // Secret for JWT signing
const resetTokens = new Map();



// Set the view engine to EJS
app.set("view engine", "ejs");

// Middleware to parse JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, "public")));

// Middleware to parse cookies
app.use(cookieParser());

// Route to render the homepage
app.get('/', (req, res) => {
    res.render("index");
});


// Route to handle user creation (registration)
app.post('/create', async (req, res) => {
    const { username, email, password } = req.body;

     // Check if the username is provided
    if (!username) {
        return res.render('registration', { errorMessage: 'Username is required', username: null });
    }
    // Validate password strength
    if (!validatePasswordStrength(password)) {
        return res.render('registration', { errorMessage: 'Password does not meet strength requirements' });
    }
    try {
        // Hash the password before storing
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);
        // Create a new user
        const createdUser = await userModel.create({
            username,
            email,
            password: hash
        });
        // Create JWT token for the user
        const token = jwt.sign({ email: createdUser.email }, JWT_SECRET);
        res.cookie("token", token, { httpOnly: true });
        res.render('registration', {username: createdUser.username});
    } catch (error) {
        // Handle server errors
        res.status(500).send({ error: 'Something went wrong!' });
    }
});

// Route to handle user logout
app.get("/logout", (req, res) => {
    res.clearCookie("token"); // Clear the cookie on logout
    res.redirect("/");  // Redirect to homepage
});

// Route to render the login page
app.get("/login", (req, res) => {
    res.render('login');
});

// Route to handle user login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Find user by emai
        const user = await userModel.findOne({ email });
        if (!user){
             return res.status(404).render('login', {message: 'user not found'});
        }
        // Compare provided password with stored hash
        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
             // Create JWT token if login is successful
            const token = jwt.sign({ email: user.email }, JWT_SECRET); 
            res.cookie("token", token, { httpOnly: true }); // Store token in HTTP-only cookie
            res.render("sucess", { username: user.username }); // Render success page with username
        } else {
          return res.status(401).render('login', {message: "Invalid credentials"});
        }
    } catch (error) {
        return res.status(500).render('login', {message:"Something went wrong"});
    }
});

// Route to render password reset request page
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password',{successMessage: null, errorMessage: null});
});

// Route to handle password reset request
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        // Find user by email
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.render('forgot-password', { successMessage: null, errorMessage: 'User not found' });
        }
        // Generate a reset token
        const resetToken = crypto.randomBytes(20).toString('hex');
        resetTokens.set(resetToken, { email, expires: Date.now() + 3600000 }); // Token expires in 1 hourr

        // Send simulated reset token
        const resetLink = `http://localhost:3000/reset/${resetToken}`;
        console.log(`Password reset link: ${resetLink}`);

        return res.render('forgot-password', { successMessage: 'Password reset link sent to console', errorMessage: null });
    } catch (error) {
        return res.render('forgot-password', { successMessage: null, errorMessage: 'Something went wrong' });
    }
});

// Function to validate password strength
const validatePasswordStrength = (password) => {
    if (password.length < 8) return false; // Check for minimum length
    let strength = 0;
    if (/[A-Z]/.test(password)) strength += 1; // Uppercase letter
    if (/[a-z]/.test(password)) strength += 1; // Lowercase letter
    if (/[0-9]/.test(password)) strength += 1; // digits
    if (/[^A-Za-z0-9]/.test(password)) strength += 1; // special charatcters

    return strength >= 4; // Require at least 4 out of 5 criteria
};
// Route to render password reset form
// Route to display the reset password form
app.get('/reset/:token', (req, res) => {
    const { token } = req.params;

    // Check if the token is valid and not expired
    const resetData = resetTokens.get(token);
    if (!resetData || resetData.expires < Date.now()) {
        return res.render('reset-password', { token: null, errorMessage: 'Invalid or expired token', successMessage: null });
    }

    // Render the password reset form
    res.render('reset-password', { token, successMessage: null, errorMessage: null });
});

// Route to handle the new password submission
app.post('/reset/:token', async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    // Check if the token is valid
    const resetData = resetTokens.get(token);
    if (!resetData || resetData.expires < Date.now()) {
        return res.render('reset-password', { token: null, errorMessage: 'Invalid or expired token', successMessage: null });
    }
    if (!validatePasswordStrength(newPassword)) {
        return res.render('reset-password', { token, errorMessage: 'Password does not meet strength requirements', successMessage: null });
    }

    try {
        // Find user and update their password
        const user = await userModel.findOne({ email: resetData.email });
        if (!user) {
            return res.render('reset-password', { token: null, errorMessage: 'User not found', successMessage: null });
        }
        const salt = await bcrypt.genSalt(10);
        // Update user's password (hash the password before storing)
        user.password = await bcrypt.hash(newPassword,salt); // Assume password hashing is done in user model middleware
        await user.save();

        // Remove the token after use
        resetTokens.delete(token);

        // Render success message
        res.render('reset-password', { token: null, successMessage: 'Your password has been successfully updated', errorMessage: null });
    } catch (error) {
        // Render error message if something goes wrong
        res.render('reset-password', { token, successMessage: null, errorMessage: 'Failed to update password' });
    }
});

app.get('/sucess', (req, res)=>{
    res.render('sucess');
})

// Start the server on port 3000
app.listen(3000, () => console.log('Server running on port 3000'));
