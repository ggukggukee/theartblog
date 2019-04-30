const express = require('express');
const app = express();
const MongoClient = require('mongodb').MongoClient;
const ObjectId = require('mongodb').ObjectID;
const methodOverride = require('method-override');
const assert = require('assert');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const passport = require("passport");
const LocalStrategy = require("passport-local");
const session = require('express-session');
const flash = require('express-flash');
const {check, validationResult} = require('express-validator/check');

//view engine for ejs
app.set('view engine', 'ejs');

//using req.body
app.use(express.urlencoded({extended: true}));
app.use(express.json());

//for delete and edit routes
app.use(methodOverride('_method'));

//setting folders
app.use(express.static('public'));
app.use(express.static('partials'));
app.use(express.static('images'));
app.use(express.static('assets'));

// using express-session for session cookies
app.use(session({
    secret: 'ahnyujin',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

app.use(flash());
app.use((req, res, next) => {
    res.locals.error = req.flash('error');
    res.locals.success = req.flash('success');
    next();
})

// Connection URL
const mongourl = process.env.DATABASE_URL 
 
// Database Name
var db;

// Use connect method to connect to the server
MongoClient.connect(mongourl, {useNewUrlParser: true}, function(err, client) {
    if(err) {
        assert.equal(null, err);
    } else {
        console.log('Connected successfully to the MongoDB server');
        db = client.db('theartblog');
    }
});

// using the local strategy with passport
passport.use(new LocalStrategy({usernameField: 'username', passwordField: 'password'}, (username, password, done) => {
    db.collection('users').findOne({user: username}, (err, user) => {
        if(err) {
            return done(err);
        } if (!user) {
            return done(null, false, {message: 'User not found'});
        } if (username === user.user && (bcrypt.compareSync(password, user.password) === false)) { 
            return done(null, false, {message: 'Incorrect password'}); 
        } if (username === user.user && (bcrypt.compareSync(password, user.password) === true)) {
            return done(null, user);
        }
    });   
}));

passport.serializeUser(function (user, done) {
    return done(null, user.id);
});
 
passport.deserializeUser(function (id, done) {
    db.collection('users').findOne({id: id}, (err, user) => {
        return done(null, user);
    });
});

//INDEX ROUTE
app.get('/', (req, res) => {
    db.collection('posts').find().sort({"_id": -1}).toArray((err, allPosts) => {
        if(err) {
            assert.equal(null, err);
        } else {
            res.render('index', {allPosts: allPosts, layout: 'index', user: req.user});
        }
    });
});

//SIGNUP ROUTE
app.get('/signup', (req, res) => {
    res.render('signup', {layout: 'signup', user: req.user});
});

app.post('/signup', [
    check('username').trim().escape(),
    check('email').trim().escape(),
    check('password').trim().escape()
], (req, res) => {
    bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
        if(err) {
            assert.equal(err, null);
        } else {
            var upsert = {upsert: true};
            var setForm = {$set:{user: req.body.username, email: req.body.email, password: hash, date: new Date}};
            db.collection('users').createIndex({user: 1}, {unique: true});
            db.collection('users').createIndex({email: 1}, {unique: true});
            db.collection('users').updateOne({user: req.body.username, email: req.body.email, password: hash, id: ObjectId().toString()}, setForm, upsert, (err, userCreated) => {
                if(err) {
                    req.flash('error', 'User with this username or email is already exist');
                    res.redirect('/signup');
                } else {
                    passport.authenticate('local')(req, res, () => {
                        req.flash('success', 'Welcome ' + req.user.user + '!');
                        res.redirect('/');
                    });
                    console.log('User created');
                }
            }); 
        }
    });
});

//LOGIN ROUTE
app.get('/login', (req, res) => {
    res.render('login', {layout: 'login', user: req.user, message: req.flash('error')});
});

app.post('/login', passport.authenticate('local', {failureRedirect: '/login', failureFlash : true}), (req, res) => {
    req.flash('success', 'Welcome back ' + req.user.user + '!');
    res.redirect('/');
});

//logout route
app.get('/logout', (req, res) => {
    req.logout();
    req.flash('success', 'Goodbye. See you next time!');
    res.redirect('/');
});

function isLoggedIn(req, res, next) {
    if(req.isAuthenticated()){
        return next();
    };
    res.redirect('/login');
};

function isSameUser(req, res, next){
    var objectId = require('mongodb').ObjectID(req.params.id);
    db.collection('posts').findOne({_id: objectId}, (err, foundPost) => {
        if(req.user.user === foundPost.user){
            return next();
        } else {
            res.redirect('back');
        }
    });
}

//add new post route
app.get('/add', isLoggedIn, (req, res) => {
    res.render('add', {layout: 'add', user: req.user, message: req.flash('error')});
});

app.post('/add', isLoggedIn, [
    check('image').trim(),
    check('title').trim().unescape(),
    check('content').trim().unescape()
], (req, res) => {
    db.collection('posts').insertOne({user: req.user.user, image: req.body.image, title: req.body.title, content: req.body.content, date: new Date}, (err, createdPost) => {
        if(err) {
            assert.equal(err, null);
        } else {
            res.redirect('/');
        }
    });
});

//show post route
app.get('/:id([0-9a-f]{24})', (req, res) => {
    var objectId = require('mongodb').ObjectID(req.params.id);
    db.collection('posts').findOne({_id: objectId}, (err, foundPost) => {
        if(err) {
            assert.equal(err, null);
        } else { 
            res.render('post', {foundPost: foundPost, layout: 'post', user: req.user});   
        }
    });
});

//edit post route
app.put('/:id', isLoggedIn, isSameUser, [
    check('image').trim(),
    check('title').trim().unescape(),
    check('content').trim().unescape()
], (req, res) => {
    var objectId = require('mongodb').ObjectID(req.params.id);
    var setUpdate = {$set:{title: req.body.title, image: req.body.image, content: req.body.content, edited: new Date}};
    db.collection('posts').updateOne({_id: objectId}, setUpdate, (err, updatedPost) => {
        if(err) {
            assert.equal(err, null);
        } else {
            res.redirect('/' + req.params.id);
        }
    });
});

//delete a post route
app.delete('/:id', isLoggedIn, isSameUser, (req, res) => {
    var objectId = require('mongodb').ObjectID(req.params.id);
    db.collection('posts').deleteOne({_id: objectId}, (err) => {
        if(err) {
            assert.equal(err, null);
        } else {
            res.redirect('/');
        }
    });
});

//edit post route
app.get('/:id/edit', isLoggedIn, isSameUser, (req, res) => {
    var objectId = require('mongodb').ObjectID(req.params.id);
    db.collection('posts').findOne({_id: objectId}, (err, foundPost) => {
        if(err) {
            assert.equal(err, null);
        } else { 
            res.render('edit', {foundPost: foundPost, layout: 'edit', user: req.user});   
        }
    });
});

//starting a server
app.listen(process.env.PORT, process.env.IP, function() {
    console.log('Blog server has been started');
});


