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

    res.cookie('token', token, { httpOnly: true }).send();
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

    res.cookie('token', token, { httpOnly: true }).send();
  } catch (err) {
    res.status(500).send();
  }
});

// check if someone is logged in
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

module.exports = router;
