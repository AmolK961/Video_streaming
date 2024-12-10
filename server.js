const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');

const fs = require('fs');


// Initialize app
dotenv.config();
const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Models
const User = require('./models/User');
const Blog = require('./models/Blog');
const Video = require('./models/Video');

// Multer for file uploads (e.g., video uploads)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// Middleware to verify JWT token and check roles
const verifyToken = (req, res, next) => {
  const token = req.cookies.auth_token;
  if (!token) return res.status(403).send('Access Denied. No token provided.');

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).send('Invalid token.');
    req.userId = decoded.userId;
    req.userRole = decoded.role;  // Add role to the request object
    next();
  });
};

// Middleware to check for role-based access (for superusers)
const isSuperUser = (req, res, next) => {
  if (req.userRole !== 'superuser') {
    return res.status(403).send('Access denied. Insufficient role.');
  }
  next();
};

// Routes

// Signup route
app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = new User({ username, email, password: hashedPassword });
  await user.save();

  res.redirect('/signin');
});

// Signin route
app.get('/signin', (req, res) => {
  res.render('signin');
});

app.post('/signin', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).send('User not found');

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).send('Invalid credentials');

  const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.cookie('auth_token', token, { httpOnly: true });
  res.redirect('/dashboard');
});

// Dashboard route (only accessible for authenticated users)
app.get('/dashboard', verifyToken, (req, res) => {
  res.render('dashboard');
});

// Video upload (only accessible by authenticated users)
app.post('/upload-video', verifyToken, upload.single('video'), async (req, res) => {
  const video = new Video({
    title: req.body.title,
    description: req.body.description,
    filePath: `/uploads/${req.file.filename}`,
  });
  await video.save();
  res.redirect('/dashboard');
});

// Blog post route (only accessible by authenticated users)
app.post('/blog', verifyToken, async (req, res) => {
  const { title, content } = req.body;
  const blogPost = new Blog({ title, content });
  await blogPost.save();
  res.redirect('/');
});

// Admin route (only accessible by superusers)
app.get('/admin', verifyToken, isSuperUser, (req, res) => {
  res.send('Super User Dashboard');
});

// Logout route
app.get('/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.redirect('/');
});

// Video route (view video details)
app.get('/video/:id', async (req, res) => {
  const video = await Video.findById(req.params.id);
  res.render('video', { video });
});

// app.js

// Route to subscribe to a content creator
app.post('/subscribe/:creatorId', verifyToken, async (req, res) => {
    const userId = req.userId;
    const creatorId = req.params.creatorId;
  
    // Find the user and the content creator
    const user = await User.findById(userId);
    const creator = await User.findById(creatorId);
  
    if (!creator || creator.role !== 'user') {
      return res.status(400).send('Invalid content creator.');
    }
  
    // Subscribe the user to the creator
    if (!user.subscriptions.includes(creatorId)) {
      user.subscriptions.push(creatorId);
      await user.save();
    }
  
    res.send('Subscription successful!');
  });
  
  // Route to unsubscribe from a content creator
  app.post('/unsubscribe/:creatorId', verifyToken, async (req, res) => {
    const userId = req.userId;
    const creatorId = req.params.creatorId;
  
    // Find the user and the content creator
    const user = await User.findById(userId);
  
    // Unsubscribe the user from the creator
    user.subscriptions = user.subscriptions.filter(sub => sub.toString() !== creatorId);
    await user.save();
  
    res.send('Unsubscribed successfully!');
  });


  // Route to get videos of subscribed creators
app.get('/subscribed-videos', verifyToken, async (req, res) => {
    const userId = req.userId;
    
    // Find the user and populate their subscriptions
    const user = await User.findById(userId).populate('subscriptions');
  
    // Fetch videos from the creators the user is subscribed to
    const subscribedVideos = await Video.find({
      'creator': { $in: user.subscriptions.map(creator => creator._id) }
    });
  
    res.render('subscribed-videos', { videos: subscribedVideos });
  });



  // Route to stream videos
app.get('/stream/:id', async (req, res) => {
    const videoId = req.params.id;
    const video = await Video.findById(videoId);
  
    if (!video) {
      return res.status(404).send('Video not found');
    }
  
    const videoPath = path.join(__dirname, 'public', video.filePath);
    const stat = fs.statSync(videoPath);
    const fileSize = stat.size;
    const range = req.headers.range;
  
    if (!range) {
      return res.status(416).send('Range header required');
    }
  
    const CHUNK_SIZE = 10 ** 6;  // 1MB per chunk
    const start = Number(range.replace(/\D/g, ''));
    const end = Math.min(start + CHUNK_SIZE, fileSize - 1);
  
    const stream = fs.createReadStream(videoPath, { start, end });
    const head = {
      'Content-Range': `bytes ${start}-${end}/${fileSize}`,
      'Accept-Ranges': 'bytes',
      'Content-Length': end - start + 1,
      'Content-Type': 'video/mp4',
    };
  
    res.writeHead(206, head);
    stream.pipe(res);
  });
  
  

// Starting the app
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
