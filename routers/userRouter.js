const router = require('express').Router();
const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

router.post('/', async (req, res) => {
  try {
    const { email, password, passwordVerify } = req.body;

    // validation

    if (!email || !password || !passwordVerify)
      return res.status(400).json({
        errorMessage: 'Please enter all required fields.',
      });

    if (password.length < 6)
      return res.status(400).json({
        errorMessage: 'Please enter a password of at least 6 characters.',
      });

    if (password !== passwordVerify)
      return res.status(400).json({
        errorMessage: 'Please enter the same password for verification.',
      });

    // check if account exist for this email

    const existingUser = await User.findOne({
      email,
    });
    // console.log(existingUser);
    if (existingUser)
      return res.status(400).json({
        errorMessage: 'An account with this email already exists',
      });

    // hash the password

    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(password, salt);

    // save the user in the database

    const newUser = new User({
      email,
      passwordHash,
    });

    const savedUser = await newUser.save();

    // create a JWT token

    const token = jwt.sign(
      {
        id: savedUser._id,
      },
      process.env.JWT_SECRET
    );
    // need to add sameSite: 'none' and secure: 'true' to be able sending cookies to external web hosting's i.e. Netlify
    res
      .cookie('token', token, {
        httpOnly: true,
        sameSite:
          process.env.NODE_ENV === 'development'
            ? 'lax'
            : process.env.NODE_ENV === 'production' && 'none',
        secure:
          process.env.NODE_ENV === 'development'
            ? false
            : process.env.NODE_ENV === 'production' && true,
      })
      .send();
  } catch (err) {
    res.status(500).send();
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // validation

    if (!email || !password)
      return res.status(400).json({
        errorMessage: 'Please enter all required fields.',
      });

    // get user account

    const existingUser = await User.findOne({
      email,
    });

    if (!existingUser)
      return res.status(401).json({
        errorMessage: 'Wrong email or password',
      });

    // compare password with hashed password using bcrypt

    const correctPassword = await bcrypt.compare(
      password,
      existingUser.passwordHash
    );

    if (!correctPassword)
      return res.status(401).json({
        errorMessage: 'Wrong email or password',
      });
    // create a JWT token

    const token = jwt.sign(
      {
        id: existingUser._id,
      },
      process.env.JWT_SECRET
    );

    // need to add sameSite: 'none' and secure: 'true' to be able sending cookies to external web hosting's i.e. Netlify
    res
      .cookie('token', token, {
        httpOnly: true,
        // default process.env.NODE_ENV is development, production string is stored in CONFIG VARS on the Heroku
        sameSite:
          process.env.NODE_ENV === 'development'
            ? 'lax'
            : process.env.NODE_ENV === 'production' && 'none',
        secure:
          process.env.NODE_ENV === 'development'
            ? false
            : process.env.NODE_ENV === 'production' && true,
      })
      .send();
  } catch (err) {
    res.status(500).send();
  }
});

// check if someone is logged in (if not logged in return null, and throw error with null also)
router.get('/loggedIn', (req, res) => {
  try {
    const token = req.cookies.token;

    if (!token) return res.json(null);

    const validatedUser = jwt.verify(token, process.env.JWT_SECRET);

    res.json(validatedUser.id);
  } catch (err) {
    return res.json(null);
  }
});

router.get('/logOut', (req, res) => {
  try {
    // we cannot remove cookie from a front end app / javascript. Because it is HTTP only. That is why we send HTTP request to the server.
    // clearCookie token works only for development, for production needs more settings
    // res.clearCookie('token').send();
    res
      .cookie('token', '', {
        httpOnly: true,
        sameSite:
          process.env.NODE_ENV === 'development'
            ? 'lax'
            : process.env.NODE_ENV === 'production' && 'none',
        secure:
          process.env.NODE_ENV === 'development'
            ? false
            : process.env.NODE_ENV === 'production' && true,
        expires: new Date(0),
      })
      .send();
  } catch (err) {
    return res.json(null);
  }
});

module.exports = router;
