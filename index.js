require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();
const port = process.env.PORT || 3002;

app.use(cors()); // Allow requests from different origins (Frontend)
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json()); // Allow JSON request bodies

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET
});

// Multer Cloudinary Storage Configuration
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'user_images',
    allowed_formats: ['jpg', 'png', 'jpeg']
  }
});
const upload = multer({ storage: storage });

// Connect to MongoDB
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
  education: String,
  imageUrl: String
});

const User = mongoose.model('User', userSchema);

// Password Validation Regex
const passwordValidationRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;

// Signup Route
app.post('/signup', upload.single('image'), async (req, res) => {
  const { username, password, confirmPassword, email, phone, education } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).json({ error: '❌ Passwords do not match' });
  }

  if (!passwordValidationRegex.test(password)) {
    return res.status(400).json({ error: '❌ Password must be at least 8 characters, contain 2 digits, 1 symbol, and uppercase & lowercase letters' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      password: hashedPassword,
      email,
      phone,
      education,
      imageUrl: req.file?.secure_url
    });

    await newUser.save();
    res.json({ message: '✅ Signup Successful!' });

  } catch (err) {
    console.error('❌ Error during signup:', err);
    res.status(500).json({ error: '❌ Error saving user' });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email: new RegExp('^' + email + '$', 'i') });

    if (!user) return res.status(400).json({ error: '❌ User not found' });

    const isPasswordCorrect = await bcrypt.compare(password.trim(), user.password.trim());

    if (isPasswordCorrect) {
      res.json({ message: '✅ Login Successful!', user });
    } else {
      res.status(400).json({ error: '❌ Invalid password' });
    }

  } catch (err) {
    console.error('❌ Error during login:', err);
    res.status(500).json({ error: '❌ Error finding user or comparing passwords' });
  }
});

// Start Server
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
