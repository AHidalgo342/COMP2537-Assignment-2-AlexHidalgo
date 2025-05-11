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

app.use(express.urlencoded({ extended: false }));

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

app.get('/', (req, res) => {
    var html = ``;

    if (req.session.authenticated) {
        html += `
        Hello, ${req.session.username}!
        <br>
        <form action='/members' method='get'>
            <button>Go to Members Area</button>
        </form>
        <form action='/logout' method='get'>
            <button>Logout</button>
        </form>
    `;
    }
    else {
        html += `
        <form action='/signUp' method='get'>
            <button>Sign Up</button>
        </form>
        <form action='/login' method='get'>
            <button>Log In</button>
        </form>
    `;
    }

    if (req.query.noSession) {
        html += `<br>You are not logged in`;
    }
    if (req.query.loggedOut) {
        html += `<br>You have logged out`;
    }

    res.send(html);
});

// other pages here
app.get('/signUp', (req, res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
        <input name='username' type='text' placeholder='username'>
        <input name='email' type='text' placeholder='email'>
        <input name='password' type='password' placeholder='password'>
        <button>Submit</button>
    </form>
    `;

    res.send(html);
});

app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;

    res.send(html);
});

app.post('/submitUser', async (req, res) => {
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

    const validName = validateName.validate({ username });
    const validPassword = validatePassword.validate({ password });
    const validEmail = validateEmail.validate({ email });

    var html = '';

    if (validName.error != null) {
        html += 'Invalid name <br>';
    }
    if (validPassword.error != null) {
        html += 'Invalid password <br>';
    }
    if (validEmail.error != null) {
        html += 'Invalid email <br>';
    }

    if (validName.error != null || validPassword.error != null || validEmail.error != null) {
        html += `
            <form action='/signUp' method='get'>
                <button>Try Again</button>
            <form>
        `;
        res.send(html);
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, password: hashedPassword, email: email });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.post('/loggingin', async (req, res) => {

    var html = ``;

    var email = req.body.email;
    var password = req.body.password;

    // validate email first
    const schema = Joi.string().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'ca'] } });
    const validationResult = schema.validate(email);

    if (validationResult.error != null) {
        console.log(validationResult.error);
        html += `Invalid Email <br>`;
    }

    // only the email is used to check the database.
    // at this point the email has already been validated for any NoSQL injection.
    const result = await userCollection.find({ email: email }).project({ email: 1, username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    if (result.length != 1) {
        console.log("user not found");
        html += `User not found <br>`;
    }

    if (result.length == 1 && await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = result[0].username; // the username is stored in the session.
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        console.log("incorrect password");
        html += `Incorrect Password <br>`;    
    }

    html += `<form action='/login' method='get'>
                <button>Try Again</button>
            <form>`;

    res.send(html);
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/?noSession=1');
        return;
    }

    const images = [
        'alien_huh.jpg',
        'alien_sandwich.jpg',
        'alien_sitting.jpg'];

    var randomImage = Math.floor(Math.random() * images.length);

    var html = `
    Hello, ${req.session.username}!
    <img src='${images[randomImage]}' width='500' height='500'>
    <br>
    <form action='/logout' method='get'>
        <button>Log Out</button>
    </form>
    `;
    res.send(html);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/?loggedOut=1');
});

// 404
app.use(function (req, res) {
    res.status(404).send("Page not found - 404");
});


app.listen(port, () => {
    console.log("Node application listening on port " + port);
});