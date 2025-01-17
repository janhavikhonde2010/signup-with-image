require('dotenv').config(); // Load environment variables

const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000; // Use environment port or default to 3000

// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));

// Connect to MongoDB Atlas using .env variable
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("✅ MongoDB Atlas connected successfully!"))
.catch(err => console.error("❌ DB Connection Error:", err));

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  email: String,
  phone: String,
  education: String
});

const User = mongoose.model('User', userSchema);

// Password Validation Regex (8 characters, 2 digits, 1 symbol, case-sensitive)
const passwordValidationRegex = /^(?=(.*[a-z]){1})(?=(.*[A-Z]){1})(?=(.*\d){2})(?=(.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]){1}).{8,}$/;

// Handle Signup Request
app.post('/signup', async (req, res) => {
  const { username, password, confirmPassword, email, phone, education } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).send('❌ Passwords do not match');
  }

  if (!passwordValidationRegex.test(password)) {
    return res.status(400).send('❌ Password must be at least 8 characters long, contain at least 2 digits, 1 symbol, and both uppercase and lowercase letters');
  }

  try {
    // Hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      password: hashedPassword,
      email,
      phone,
      education
    });

    await newUser.save();
    
    res.send(`
      <html>
        <body style="text-align:center; font-family:Arial;">
          <h2>✅ Signup Successful!</h2>
          <p>Your account has been created. Please log in now:</p>
          <a href="/login">Go to Login</a>
        </body>
      </html>
    `);

  } catch (err) {
    console.error('❌ Error during signup:', err);
    res.status(500).send('❌ Error hashing password or saving user');
  }
});

// Handle Login Request
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email: new RegExp('^' + email + '$', 'i') });

    if (!user) {
      return res.status(400).send('❌ User not found');
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (isPasswordCorrect) {
      res.send(`
        <html>
          <body style="text-align:center; font-family:Arial;">
            <h2>✅ Login Successful!</h2>
            <p>Welcome back, ${user.username}!</p>
          </body>
        </html>
      `);
    } else {
      res.status(400).send('❌ Invalid password');
    }

  } catch (err) {
    console.error('❌ Error during login:', err);
    res.status(500).send('❌ Error finding user or comparing passwords');
  }
});

// Serve Login Page
app.get('/login', (req, res) => {
  res.send(`
    <html>
      <body style="text-align:center; font-family:Arial;">
        <h2>Login</h2>
        <form action="/login" method="POST">
          <input type="email" name="email" placeholder="Email" required><br>
          <input type="password" name="password" placeholder="Password" required><br>
          <button type="submit">Login</button>
        </form>
        <p>Don't have an account? <a href="/">Sign up here</a></p>
      </body>
    </html>
  `);
});

// Serve Signup Page
app.get('/', (req, res) => {
  res.send(`
    <html>
      <body style="text-align:center; font-family:Arial;">
        <h2>Signup</h2>
        <form action="/signup" method="POST">
          <input type="text" name="username" placeholder="Username" required><br>
          <input type="email" name="email" placeholder="Email" required><br>
          <input type="password" name="password" placeholder="Password" required><br>
          <input type="password" name="confirmPassword" placeholder="Confirm Password" required><br>
          <input type="text" name="phone" placeholder="Phone" required><br>
          <input type="text" name="education" placeholder="Education" required><br>
          <button type="submit">Sign Up</button>
        </form>
        <p>Already have an account? <a href="/login">Login here</a></p>
      </body>
    </html>
  `);
});

// Start Server
app.listen(port, () => {
  console.log(`🚀 Server is running on http://localhost:${port}`);
});
