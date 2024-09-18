// require('dotenv').config();
// const cookieParser = require('cookie-parser');
// const express = require('express');
// const userModel = require("./models/User");
// const app = express();
// const path = require('path');
// const bcrypt = require('bcrypt');
// const jwt = require('jsonwebtoken');


// //set the view engine to EJS
// app.set("view engine", "ejs");

// //Middleware to parse JSON and URL-encoded data
// app.use(express.json());
// app.use(express.urlencoded({extended: true}));

// // Serve static files from the public directory
// app.use(express.static(path.join(__dirname, "public")));
// // Middleware to parse cookies
// app.use(cookieParser());

// // Route to render the homepage
// app.get('/', (req, res) =>{
//     res.render("index");
// });


// // Route to handle user creation (registration)
// app.post('/create', async (req, res)=>{
//     let {username, email, password} = req.body; 

//     // Generate a salt and hash the password
//     bcrypt.genSalt(10, (err, salt)=>{
//         bcrypt.hash(password, salt, async (err, hash) =>{
//              // Create a new user with hashed password
//             let createduser = await userModel.create({
//                 username,
//                 email,
//                 password: hash
//              })
//              // Create a JWT token with email
//              let token = jwt.sign({email}, "secret");
//              // Set the token as a cookie
//              res.cookie("token", token);
//              // Send the created user as a response
//              res.send(createduser);
//         })
//     })
// });
// // Route to handle user logout
// app.get("/logout", (req, res)=>{
//     // Clear the token cookie
//     res.cookie("token", "");
//     // Redirect to the homepage
//     res.redirect("/");
// });
// // Route to render the login page
// app.get("/login", (req, res) =>{
//     res.render('login')
// });
// // Route to handle user login
// app.post('/login', async (req, res) =>{

//  // Find a user by email
//     let user = await userModel.findOne({email: req.body.email});
//      // If user is not found, send an error message
//     if(!user) return res.send("something went wrong");
//     // Compare the provided password with the hashed password
//     bcrypt.compare(req.body.password, user.password, (err, result)=>{
//         // If the password matches, create a JWT token
//         if(result){
//             let token = jwt.sign({email: user.email}, "secret");
//              // Set the token as a cookie
//              res.cookie("token", token);
//              // Send a success message
//             res.send("yes you can login");
//         }
//         //if password is wrong it displays you can't login
//         else res.send("you can't login")
//     })
// });

// // Start the server on port 3000
// app.listen(3000);
require('dotenv').config();    // Load environment variables from .env file
const cookieParser = require('cookie-parser');
const express = require('express');
const userModel = require("./models/User");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const path = require('path');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";

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
app.post('/create', 
    body('username').notEmpty().withMessage('Username is required'),
    body('email').isEmail().withMessage('Invalid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, password } = req.body;

        try {
            const salt = await bcrypt.genSalt(10);
            const hash = await bcrypt.hash(password, salt);

            const createdUser = await userModel.create({
                username,
                email,
                password: hash
            });

            const token = jwt.sign({ email: createdUser.email }, JWT_SECRET);
            res.cookie("token", token, { httpOnly: true });
            res.status(201).json(createdUser);
        } catch (error) {
            res.status(500).json({ error: 'Something went wrong!' });
        }
    }
);

// Route to handle user logout
app.get("/logout", (req, res) => {
    res.clearCookie("token");
    res.redirect("/");
});

// Route to render the login page
app.get("/login", (req, res) => {
    res.render('login');
});

// Route to handle user login
app.post('/login',
    body('email').isEmail().withMessage('Invalid email'),
    body('password').notEmpty().withMessage('Password is required'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        try {
            const user = await userModel.findOne({ email });
            if (!user) return res.status(404).send("User not found");

            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                const token = jwt.sign({ email: user.email }, JWT_SECRET);
                res.cookie("token", token, { httpOnly: true });
                res.send("Login successful");
            } else {
                res.status(401).send("Invalid credentials");
            }
        } catch (error) {
            res.status(500).send("Something went wrong");
        }
    }
);

// Route to render password reset request page
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password');
});

// Route to handle password reset request
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await userModel.findOne({ email });
        if (!user) return res.status(404).send("User not found");

        // Generate a reset token
        const resetToken = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        await user.save();

        // Send email with reset token
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        const mailOptions = {
            to: email,
            from: 'passwordreset@example.com',
            subject: 'Password Reset',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
            Please click on the following link, or paste this into your browser to complete the process:\n\n
            http://${req.headers.host}/reset/${resetToken}\n\n
            If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };

        await transporter.sendMail(mailOptions);

        res.status(200).send('Password reset link sent');
    } catch (error) {
        res.status(500).send('Something went wrong');
    }
});

// Route to render password reset form
app.get('/reset/:token', (req, res) => {
    res.render('reset', { token: req.params.token });
});

// Route to handle password reset
app.post('/reset/:token', async (req, res) => {
    const { password } = req.body;
    const resetToken = req.params.token;

    try {
        const user = await userModel.findOne({
            resetPasswordToken: resetToken,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) return res.status(400).send('Password reset token is invalid or has expired');

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        user.password = hash;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        await user.save();

        res.status(200).send('Password has been reset');
    } catch (error) {
        res.status(500).send('Something went wrong');
    }
});

// Start the server on port 3000
app.listen(3000, () => console.log('Server running on port 3000'));
