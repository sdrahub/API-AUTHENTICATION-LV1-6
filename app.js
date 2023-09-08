//jshint esversion:6//

import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import mongoose from "mongoose";
//import encrypt from "mongoose-encryption"; //level 2
//import md5 from 'md5'; // level 3
//import bcrypt from "bcrypt"; //level 4
//const saltRounds = 10; //level 4

import session from "express-session"; //level 5
import passport from "passport"; //level 5
import passportLocalMongoose from "passport-local-mongoose"; //level 5
import { Strategy as GoogleStrategy } from "passport-google-oauth20"; // level 6

import findOrCreate from "mongoose-findorcreate";

const app = express();

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

//level 5
app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

//level 1
//const userSchema = {
// email: String,
//  password: String
//};

//level 2 level 3 level 4
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose); // level 5
userSchema.plugin(findOrCreate); //level 6

//level 2 & level 3
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = mongoose.model("User", userSchema);

// createStrategy" for local strategy level 5
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support level 5

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

//level 6 google
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", (req, res) => {
  res.render("home");
});

//google
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

//google
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  }
);

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", async (req, res) => {
  //level 5
  //if (req.isAuthenticated()) {
    //res.render("secrets");
 // } else {
   // res.redirect("login");
 // }

  //level 6
  try {
    const foundUsers = await User.find({ secret: { $ne: null } });
    if (foundUsers) {
      res.render("secrets", { userWithSecrets: foundUsers });
    }
  } catch (err) {
    console.log(err);
  }
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("login");
  }
});

app.post("/submit", async (req, res) => {
  const submittedSecret = req.body.secret;

  // once the user is authenticated and their session gets save,
  //their user details are save to req.user
  try {
    const foundUser = await User.findById(req.user.id);
    if (foundUser) {
      foundUser.secret = submittedSecret;
      foundUser.save();
      res.redirect("/secrets");
    }
  } catch (err) {
    console.log(err);
  }
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

//app.post("/register", async (req, res) => {
//const hash = bcrypt.hashSync(req.body.password, saltRounds); //level 4

//const newUser = new User({
// email: req.body.username,
//password: req.body.password, //level 1 & level 2
//password :md5(req.body.password) //level 3

// password: hash, //level 4
//});
// try {
//await newUser.save();
//res.render("secrets");
//} catch (err) {
//  res.send();
// }
//});

//app.post("/login", async (req, res) => {

//const username = req.body.username;
//const password = req.body.password; //level 1 level 2 level 4
//const password = md5(req.body.password); //level 3

//try {
//const foundUser = await User.findOne({ email: username });
//if (foundUser) {
//if (foundUser.password === password){   //level 1 level 2 &level 3
//if (bcrypt.compareSync(password, foundUser.password)) {
//   res.render("secrets");
// } else {
//    console.log("password doesn't match...try again");
//res.redirect("/register");
//  }
// } else {
//   console.log("user not found.");
//res.redirect("/register");
// }
// } catch (err) {
//  console.log(err);
// }
//});

//level 5 & 6
app.post("/register", async (req, res) => {
  try {
    User.register({ username: req.body.username }, req.body.password);
    passport.authenticate("local")(req, res, () => {
      res.redirect("/secrets");
    });
  } catch (err) {
    console.log(err);
    res.redirect("/register");
  }
});

app.post("/login", async (req, res) => {
  const newUser = new User({
    username: req.body.username,
    password: req.body.password,
  });
  try {
    req.login(newUser, (err) => {
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    });
  } catch (err) {
    console.log(err);
  }
});

app.listen(3000, function () {
  console.log("server started on port 3000");
});
