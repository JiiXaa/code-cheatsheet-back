const PORT = process.env.PORT;

const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const cookieParser = require('cookie-parser');

dotenv.config();

// setup express server

const app = express();

app.use(express.json());
app.use(
  cors({
    origin: ['http://localhost:3000', 'https://code-cheatsheet.netlify.app'],
    credentials: true,
  })
);
app.use(cookieParser());

app.listen(PORT, () => console.log(`server started on port ${PORT}`));

// set up routers

app.use('/snippet', require('./routers/snippetRouter'));
app.use('/auth', require('./routers/userRouter'));

// connect to mongoDB

mongoose.connect(
  process.env.MDB_CONNECT_STRING,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
  (err) => {
    if (err) return console.error(err);
    console.log('Connected to MongoDB');
  }
);
