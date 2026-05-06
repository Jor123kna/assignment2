require('./utils.js');
require('dotenv').config(); 
const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const MongoStore = require('connect-mongo').default;
const saltRounds = 12;

const User = require('./models/users');
const app = express();

const Joi = require('joi');

const expireTime = 1 * 60 * 60 * 1000;


app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

var mongoStore = MongoStore.create({
	    mongoUrl: process.env.MONGODB_URI,
        crypto: {
            secret: process.env.MONGODB_SESSION_SECRET
        }
});

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: mongoStore,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: expireTime }
}));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.log("MongoDB connection error:", err));

const PORT = process.env.PORT || 3000;


// HOME PAGE
app.get('/', (req, res) => {

    if (!req.session.userId) {
        res.send(`
            <h1>Welcome</h1><br>
            <button onclick="window.location.href='/signup'">Sign up</button><br>
            <button onclick="window.location.href='/login'">Login</button>
            
        `);
    } else {
        res.send(`
            <h1>Hello, ${req.session.name}</h1>
            <button onclick="window.location.href='/members'">Go to Members Area</button><br><br>
            <button onclick="window.location.href='/logout'">Logout</button>
        `);
    }

});

// SIGNUP PAGE
app.get('/signup', (req, res) => {
    res.send(`
        <h1>Create User</h1>
        <form action="/signup" method="POST">
            <input type="text" name="name" placeholder="Name" required><br>
            <input type="email" name="email" placeholder="Email" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">Submit</button>
        </form>
    `);
});

// LOGIN PAGE
app.get('/login', (req, res) => {
   res.send(`
        <h1>Login</h1>
        <form action="/login" method="POST">
            <input type="email" name="email" placeholder="Email" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>
    `);
});

// SIGNUP POST
app.post('/signup', async (req, res) => {
    try {
        const schema = Joi.object({
            name: Joi.string().max(50).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(50).required()
        });

        const validationResult = schema.validate(req.body);

        if (validationResult.error) {
            return res.send("Invalid input. <a href='/signup'>Try again</a>");
        }

        const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);

        const user = new User({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        });

        const savedUser = await user.save();

        req.session.userId = user._id;
        req.session.name = user.name;

        res.redirect("/members");

    } catch (error) {
        console.error(error);
        res.send("Error adding user" + error.message);
    }
});

// LOGIN POST
app.post('/login', async (req, res) => {

    try {
        const schema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().max(50).required()
        });

        const validationResult = schema.validate(req.body);

        if (validationResult.error) {
            return res.send("Invalid email or password. <a href='/login'>Try again</a>");
        }

        const { email, password } = req.body;

        const user = await User.findOne({ email: email });

        if (!user) {
            return res.send("User not found");
        }

        const passwordMatches = await bcrypt.compare(password, user.password);

        if (!passwordMatches) {
            return res.send("Incorrect password");
        }

        req.session.userId = user._id;
        req.session.name = user.name;

        res.redirect("/members");

    } catch (error) {
        console.error(error);
        res.send("Error logging in");
    }
});

app.get('/members', (req, res) => {

    if (!req.session.userId) {
        return res.redirect("/");
    }

    const images = [
        '/noEars.gif',
        '/umm.gif',
        '/waterDontCare.gif'
    ];

    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <h1>Members Area</h1>
        <p>Welcome ${req.session.name}</p>
        <img src='${randomImage}' style='width:250px;'>
        <br><br>
        <button onclick="window.location.href='/logout'">Sign out</button>   
     `);
});

// LOGOUT
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
            return res.send("Error logging out");
        }

        res.redirect("/");
    });
});

// 404
app.use((req, res) => {
    res.status(404).send("404 Not Found");
});

// ERROR HANDLER
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send("500 Internal Server Error");
});

// START SERVER
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});