//external node module for environment variables, need to be on top
require('dotenv').config()

//native node modules
const https = require("https");

//external node modules, installed via npm
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const ejs = require("ejs");
//Old modules, used in previos version of page, while learning authentication
//const md5 = require("md5");
//const bcrypt = require('bcrypt');
//Salt rounds for bcrypt
//const saltRounds = 10;
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


//Express initialization
//Use ejs
app.set('view engine', 'ejs');

//Use body parser - so you can use req.body.variableName
app.use(bodyParser.urlencoded({
  extended: true
}));

//Use static folder "public"
app.use(express.static("public"));

//Create session
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

//Initialization of passport
app.use(passport.initialize());
//Tell passport to use our session
app.use(passport.session());

//Database initialization
// mongoose.connect("mongodb://localhost:27017/userDB", {
//   useNewUrlParser: true,
//   useUnifiedTopology: true
// });

const dbURI = "mongodb+srv://admin-krupiceva:" + process.env.MONGO_DB_ATLAS_PASS + "@cluster0.pra2j.mongodb.net/userDB"
mongoose.connect(dbURI, {useNewUrlParser: true, useUnifiedTopology: true});

//User Schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

//Use passport-local-mongoose with User Schema
userSchema.plugin(passportLocalMongoose);

//Use mongoose-findorcreate with User userSchema
userSchema.plugin(findOrCreate);

//Create a DB model
const User = mongoose.model("User", userSchema);

//Setting up passport-local strategy
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//Setting Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//Get route for homepage
app.get("/", function(req, res) {
  res.render("home");
});

//Authentication route
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);
//If user is successffuly authenticate then rediret him to secret page
app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

//Route for user login
app.route("/login")
  .get(function(req, res) {
    res.render("login");
  })
  .post(function(req, res) {
    /******Version with bcrypt******/
    // const username = req.body.username;
    // const password = req.body.password;
    // User.findOne({email: username}, function(err, foundUser) {
    //   if (err) {
    //     console.log(err);
    //   } else {
    //     if (foundUser) {
    //       bcrypt.compare(password, foundUser.password, function(err, result) {
    //         if (result === true) {
    //           res.render("secrets");
    //         }
    //       });
    //     }
    //   }
    // });

    /*****Version with passport-local-mongoose******/
    const user = new User({
      username: req.body.username,
      password: req.body.password
    });
    req.login(user, function(err){
      if(err){
        console.log(err);
      } else{
        passport.authenticate("local")(req, res, function(){
          res.redirect("/secrets");
        });
      }
    });
  });

//Route for user registration
app.route("/register")
  .get(function(req, res) {
    res.render("register");
  })
  .post(function(req, res) {
    /******Version with bcrypt******/
    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //   const newUser = new User({
    //     email: req.body.username,
    //     password: hash
    //   });
    //
    //   newUser.save(function(err) {
    //     if (err) {
    //       console.log(err);
    //     } else {
    //       res.render("secrets");
    //     }
    //   });
    // });

    /*****Version with passport-local-mongoose******/
    User.register({username: req.body.username}, req.body.password, function(err, user){
      if(err){
        console.log(err);
        res.redirect("/register");
      } else{
        passport.authenticate("local")(req, res, function(){
          res.redirect("/secrets");
        });
      }
    });
  });

//Route for secret page, find all secrets from user that have secrets
app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    } else{
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

//Route for submit a secret page
app.route("/submit")
.get(function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else{
    res.redirect("/login");
  }
})
.post(function(req, res){
  const submittedSecret = req.body.secret;
  //Add new secret to the logged user
  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    } else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

//Route for logging out user
app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

//Start server
app.listen(process.env.PORT || 3000, function() {
  console.log("Server started successffuly");
});
