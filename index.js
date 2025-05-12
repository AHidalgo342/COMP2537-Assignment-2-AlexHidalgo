require("./utils.js");
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const port = process.env.PORT || 3000;

const app = express();

const expireTime = 60 * 60 * 1000;

const saltRounds = 10;

app.use(express.static(__dirname + "/public"));
app.use(express.urlencoded({ extended: false }));
app.set('view engine', 'ejs');

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}));

/* authorization middleware */
function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", { error: "Yeaaahhhhh sorry, but it turns out you're Not Authorized to see this page :(" });
        return;
    }
    else {
        next();
    }
}
/* authorization middleware END */


app.get('/', (req, res) => {
    var authenticated = req.session.authenticated;
    var loggedOut = req.query.loggedOut;
    var user = req.session.username;

    res.render("index", {
        authenticated: authenticated,
        loggedOut: loggedOut,
        user: user
    });
});

app.get('/signUp', (req, res) => {
    res.render("signup");
});

app.get('/login', (req, res) => {
    res.render("login");
});

app.post('/signupSubmit', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;

    const validateName = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required()
        });
    const validatePassword = Joi.object(
        {
            password: Joi.string().max(20).required()
        });

    const validateEmail = Joi.object(
        {
            email: Joi.string().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'ca'] } }).required()
        });

    const invalidName = validateName.validate({ username });
    const invalidPassword = validatePassword.validate({ password });
    const invalidEmail = validateEmail.validate({ email });

    // if you encounter an error at all, catch them here.
    if (invalidName.error != null || invalidPassword.error != null || invalidEmail.error != null) {
        res.render('signupSubmit', {
            invalidName: invalidName,
            invalidPassword: invalidPassword,
            invalidEmail: invalidEmail
        });
        return;
    }
    // else create the acccount

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, password: hashedPassword, email: email, user_type: "user" });
    console.log("Inserted user");

    // and log them in
    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    // validate email first
    const schema = Joi.string().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'ca'] } });
    const validationResult = schema.validate(email);

    // invalid email?
    if (validationResult.error != null) {
        res.render("loginSubmit", {
            invalidEmail: 1,
            userNotFound: 0,
            wrongPassword: 0
        });
        return;
    }

    // only the email is used to check the database.
    // at this point the email has already been validated for any NoSQL injection.
    const result = await userCollection.find({ email: email }).project({ email: 1, username: 1, password: 1, user_type: 1, _id: 1 }).toArray();

    console.log(result);

    // account not found?
    if (result.length != 1) {
        res.render("loginSubmit", {
            invalidEmail: 0,
            userNotFound: 1,
            wrongPassword: 0
        });
        return;
    }

    // if there is an account, check it's password.
    if (result.length == 1 && await bcrypt.compare(password, result[0].password)) {

        console.log("correct password");

        req.session.authenticated = true;
        req.session.username = result[0].username; // the username is stored in the session.
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        // if it's the wrong password, boot 'em out
        res.render("loginSubmit", {
            invalidEmail: 0,
            userNotFound: 0,
            wrongPassword: 1
        });
        return;
    }
});

// can't view if you're not a member
app.get('/members', sessionValidation, (req, res) => {
    res.render("members");
});

// can't view if you're not a member OR not an admin
app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({ username: 1, email: 1, user_type: 1 }).toArray();

    res.render("admin", { users: result });
});

// no session? not admin? sorryyyyyy
app.get('/users/:user/:type', sessionValidation, adminAuthorization, async (req, res) => {

    var username = req.params.user;
    var user_type = req.params.type;

    console.log(username, user_type);

    // check for malicious usernames
    const validateName = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required()
        });
    const invalidName = validateName.validate({ username });

    // this is a two in one
    // if the given user_type is not the following two, you're booted
    // and if there's an error with the name, same thing.
    if ((user_type != 'admin' && user_type != 'user') || invalidName.error != null) {
        res.render("errorMessage", { error: "What, are you TRYING to break something?" });
        return;
    }

    // Check for a match before updating the user_type
    await userCollection.findOneAndUpdate({ username: username },
        {
            $set: { 'user_type': user_type },
            $currentDate: { lastModified: true }
        });

    res.redirect("/admin");
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/?loggedOut=1');
});

// 404
app.use(function (req, res) {
    res.status(404).render("404");
});


app.listen(port, () => {
    console.log(`Node application listening on http://localhost:${port}`);
});