//jshint esversion:6
require("dotenv").config();
const bodyParser = require("body-parser");
const express = require("express");
const app = express();
//PASSPORT 1
const session = require("express-session");
const passport = require("passport");
const passportlocalmongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate"); //to create findOrCreate function for google authentication
// const bcrypt = require("bcrypt"); going to use PASSPORT for more authentication
// const saltRounds = 10;
// var md5 = require('md5'); overtaken by bcrypt
// const encrypt = require("mongoose-encryption"); overtaken by hashing token:1

const port = 3000;
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

//PASSPORT 2
app.use(
  session({
    secret: "our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

//PASSPORT 3
app.use(passport.initialize());
app.use(passport.session());

const mongoose = require("mongoose");
const { authenticate } = require("passport");
//Set up default mongoose connection
const url =
  "mongodb+srv://" +
  process.env.USERNAMEE +
  ":" +
  process.env.PASSWORD +
  "@cluster0.qcanqcf.mongodb.net/Secrets";

mongoose.connect(url, { useNewUrlParser: true });
//Get the default connection

const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
});

//PASSPORT 4
UserSchema.plugin(passportlocalmongoose);
UserSchema.plugin(findOrCreate);

// UserSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] }); overtaken by hashing token:1
// Compile model from schema
var User = mongoose.model("User", UserSchema);

//PASSPORT 5
passport.use(User.createStrategy());

/* passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser()); */
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture,
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

//--------GOOGLE AUTHENTICATION---------
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );

  //--------HASHING------------
  /* bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    // Store hash in your password DB.
    const newuser = new User({
      email: req.body.username,
      password: hash,
      // password: md5(req.body.password), overtaken by bcrypt
    });
    newuser.save(function (err) {
      if (err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    });
  }); */
});

app.post(
  "/login",
  passport.authenticate("local") /* checking for authentication in PASSPORT */,
  function (req, res) {
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });
    req.login(user, function (err) {
      if (err) {
        console.log(err);
      } else {
        res.redirect("/secrets");
      }
    });
    //--------HASHING------------
    /* const username = req.body.username;
  const password = req.body.password;
  //   const password = md5(req.body.password);overtaken by bcrypt
  User.findOne({ email: username }, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, function (err, result) {
          if (result === true) {
            res.render("secrets");
            // result == true
          }
        });
      }
    }
  }); */
  }
);

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
