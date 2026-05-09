require('./utils.js');
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const MongoStore = require('connect-mongo').default;
const Joi = require('joi');

const User = require('./models/users');

const app = express();

const saltRounds = 12;
const expireTime = 1 * 60 * 60 * 1000; // 1 hour

app.set('view engine', 'ejs');

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// SESSION STORE
const mongoStore = MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 60 * 60,
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

// CONNECT TO MONGODB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.log("MongoDB connection error:", err));

const PORT = process.env.PORT || 3000;

// MIDDLEWARE FUNCTIONS
const validateSession = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    next();
};

const requireAdmin = (req, res, next) => {
    if (!req.session.isAdmin) {
        return res.status(403).render("403", {
            message: "You are not authorized to view this page."
        });
    }

    next();
};

const validateNoSession = (req, res, next) => {
    if (req.session.userId) {
        return res.redirect("/members");
    }

    next();
}

// HOME PAGE
app.get('/', (req, res) => {
    res.render('index', {
        loggedIn: !!req.session.userId,
        name: req.session.name,
        isAdmin: req.session.isAdmin
    });
});

// SIGNUP PAGE
app.get('/signup', validateNoSession, (req, res) => {
    res.render("signup");
});

// LOGIN PAGE
app.get('/login', validateNoSession, (req, res) => {
    res.render("login");
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
            return res.render("signup", {
                message: "Please provide a valid name, email, and password."
            });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);

        const user = new User({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
            isAdmin: false
        });

        await user.save();

        req.session.userId = user._id;
        req.session.name = user.name;
        req.session.isAdmin = user.isAdmin;

        res.redirect("/members");

    } catch (error) {
        console.error(error);

        res.render("signup", {
            message: "Error adding user. This email may already be in use."
        });
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
            return res.render("login", {
                message: "Invalid email or password."
            });
        }

        const { email, password } = req.body;

        const user = await User.findOne({ email: email });

        if (!user) {
            return res.render("login", {
                message: "User not found."
            });
        }

        const passwordMatches = await bcrypt.compare(password, user.password);

        if (!passwordMatches) {
            return res.render("login", {
                message: "Incorrect password."
            });
        }

        req.session.userId = user._id;
        req.session.name = user.name;
        req.session.isAdmin = user.isAdmin;

        res.redirect("/members");

    } catch (error) {
        console.error(error);

        res.render("login", {
            message: "Error logging in."
        });
    }
});

// MEMBERS PAGE
app.get('/members', validateSession, (req, res) => {
    res.render("members", {
        name: req.session.name
    });
});

// ADMIN PAGE
app.get('/admin', validateSession, requireAdmin, async (req, res) => {
    try {
        const users = await User.find({});

        res.render("admin", {
            users: users
        });

    } catch (error) {
        console.error(error);
        res.send("Error fetching users");
    }
});

// PROMOTE USER TO ADMIN
app.get('/promote/:id', validateSession, requireAdmin, async (req, res) => {
    try {
        const schema = Joi.object({
            id: Joi.string().hex().length(24).required()
        });

        const validationResult = schema.validate(req.params);

        if (validationResult.error) {
            return res.status(400).send("Invalid user ID");
        }

        await User.updateOne(
            { _id: req.params.id },
            { $set: { isAdmin: true } }
        );

        res.redirect('/admin');

    } catch (error) {
        console.error(error);
        res.send("Error promoting user");
    }
});

// DEMOTE ADMIN TO USER
app.get('/demote/:id', validateSession, requireAdmin, async (req, res) => {
    try {
        const schema = Joi.object({
            id: Joi.string().hex().length(24).required()
        });

        const validationResult = schema.validate(req.params);

        if (validationResult.error) {
            return res.status(400).send("Invalid user ID");
        }

        await User.updateOne(
            { _id: req.params.id },
            { $set: { isAdmin: false } }
        );

        res.redirect('/admin');

    } catch (error) {
        console.error(error);
        res.send("Error demoting user");
    }
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
    res.status(404).render("404");
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