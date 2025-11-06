require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const saltRounds = 12;

const database = require("./databaseConnection");
const app = express();
app.use(express.static(__dirname + "/public"));

const port = process.env.PORT || 3001;
const expireTime = 60 * 60 * 1000; // 1 hour in milliseconds

/* Secret information section */
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only image files are allowed!'), false);
  }
});

app.set("view engine", "ejs");

// MongoDB session store
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@cluster0.sehwz.mongodb.net`,
  crypto: { secret: mongodb_session_secret },
});
app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: { maxAge: expireTime },
  })
);

// expose auth state and helper functions to views
app.use((req, res, next) => {
  res.locals.loggedIn = !!req.session.authenticated;
  res.locals.username = req.session.username || null;
  next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Ensure users table exists
async function ensureUsersTable() {
  const createSQL = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `;
  try {
    await database.query(createSQL);
    console.log("Users table is ready!");
  } catch (err) {
    console.error("Error ensuring users table:", err);
  }
}

ensureUsersTable();

function ensureLoggedIn(req, res, next) {
  if (!req.session.authenticated) return res.redirect("/login");
  next();
}

function ensureLoggedOut(req, res, next) {
  if (req.session.authenticated) return res.redirect("/");
  next();
}

async function getUserId(req) {
  if (req.session?.userId) return req.session.userId;
  const username = req.session.username;
  if (!username) return null;
  const [rows] = await database.query("SELECT id FROM users WHERE username = ?", [username]);
  if (!rows || rows.length === 0) return null;
  req.session.userId = rows[0].id;
  return rows[0].id;
}

app.get("/", async (req, res) => {
  try {
    res.render("index", {
    });
  } catch (err) {
    console.error("Error loading dashboard:", err);
  }
});

// Profile page
app.get("/profile", ensureLoggedIn, async (req, res) => {
  try {
    if (!user) return res.redirect("/");
    res.render("profile", { user });
  } catch (err) {
    console.error("Error loading profile:", err);
    res.redirect("/");
  }
});

// Upload profile picture
app.post("/profile/upload", ensureLoggedIn, upload.single('profilePic'), async (req, res) => {
  try {
    if (!req.file) {
      return res.redirect("/profile");
    }
    const userId = await getUserId(req);
    // Upload to Cloudinary
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        { folder: 'profile_pictures' },
        (error, result) => (error ? reject(error) : resolve(result))
      );
      uploadStream.end(req.file.buffer);
    });
    // Update user profile picture
    await database.query(
      "UPDATE users SET profile_picture = ? WHERE id = ?",
      [result.secure_url, userId]
    );
    return res.redirect("/profile");
  } catch (err) {
    console.error("Error uploading profile picture:", err);
    return res.redirect("/profile");
  }
});

// Login (public)
app.get("/login", ensureLoggedOut, (req, res) => {
  res.render("login", { error: null });
});

// Login (MySQL + bcrypt)
app.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.render("login", { error: "Please enter both username and password." });
  }
  try {
    const [rows] = await database.query(
      "SELECT id, username, password FROM users WHERE username = ?",
      [username]
    );
    if (!rows || rows.length === 0) {
      return res.render("login", { error: "Invalid username or password." });
    }
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.render("login", { error: "Invalid username or password." });
    req.session.authenticated = true;
    req.session.username = user.username;
    return res.redirect("/");
  } catch (err) {
    console.error("Error logging in:", err);
    return res.render("login", { error: "An error occurred while logging in. Please try again." });
  }
});

// Sign Up (public)
app.get("/signup", ensureLoggedOut, (req, res) => {
  const missingField = null;
  res.render("signup", { missingField });
});

// Sign Up (MySQL + bcrypt)
app.post("/signup", ensureLoggedOut, async (req, res) => {
  const username = (req.body.username || "").trim();
  const password = req.body.password || "";

  if (!username || !password) {
    const missingField = !username ? "username" : "password";
    return res.render("signup", { missingField });
  }

  // Password policy: >= 10 chars, at least one upper, lower, digit, symbol
  const strong = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{10,}$/;
  if (!strong.test(password)) {
    return res.render("signup", {
      missingField: "Password must be ≥ 10 characters and include uppercase, lowercase, a number, and a symbol.",
    });
  }

  try {
    const hashed = await bcrypt.hash(password, saltRounds);
    await database.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashed]);
    req.session.authenticated = true;
    req.session.username = username;
    return res.redirect("/");
  } catch (err) {
    console.error("Error signing up:", err.message);
    return res.render("signup", { missingField: "username (already taken?)" });
  }
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// 404 page
app.use((req, res) => {
  res.status(404).render("404");
});

// Start server
app.listen(port, () => {
  console.log(`Node application listening on port ${port}`);
});