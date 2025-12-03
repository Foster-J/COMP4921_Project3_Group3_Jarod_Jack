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

// Ensure calendar_events table exists
async function ensureCalendarEventsTable() {
  const createSQL = `
    CREATE TABLE IF NOT EXISTS calendar_events (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      start_datetime DATETIME NOT NULL,
      end_datetime DATETIME NOT NULL,
      color VARCHAR(7) DEFAULT '#3b82f6',
      deleted_at DATETIME NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_user_id (user_id),
      INDEX idx_start_datetime (start_datetime),
      INDEX idx_deleted_at (deleted_at)
    );
  `;
  try {
    await database.query(createSQL);
    console.log("Calendar events table is ready!");
  } catch (err) {
    console.error("Error ensuring calendar_events table:", err);
  }
}

// Ensure friendships table exists
async function ensureFriendshipsTable() {
  const createSQL = `
    CREATE TABLE IF NOT EXISTS friendships (
      id INT AUTO_INCREMENT PRIMARY KEY,
      requester_id INT NOT NULL,
      addressee_id INT NOT NULL,
      status ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (addressee_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE KEY unique_friendship (requester_id, addressee_id),
      INDEX idx_requester (requester_id),
      INDEX idx_addressee (addressee_id),
      INDEX idx_status (status)
    );
  `;
  try {
    await database.query(createSQL);
    console.log("Friendships table is ready!");
  } catch (err) {
    console.error("Error ensuring friendships table:", err);
  }
}

// Ensure event_participants table exists
async function ensureEventParticipantsTable() {
  const createSQL = `
    CREATE TABLE IF NOT EXISTS event_participants (
      id INT AUTO_INCREMENT PRIMARY KEY,
      event_id INT NOT NULL,
      user_id INT NOT NULL,
      role ENUM('owner','attendee') DEFAULT 'attendee',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (event_id) REFERENCES calendar_events(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE KEY unique_event_user (event_id, user_id),
      INDEX idx_event (event_id),
      INDEX idx_user (user_id)
    );
  `;
  try {
    await database.query(createSQL);
    console.log("Event participants table is ready!");
  } catch (err) {
    console.error("Error ensuring event_participants table:", err);
  }
}

// Permanently remove events that were deleted more than 30 days ago
async function purgeOldDeletedEvents() {
  try {
    await database.query(
      "DELETE FROM calendar_events WHERE deleted_at IS NOT NULL AND deleted_at < (NOW() - INTERVAL 30 DAY)"
    );
    console.log("Old soft-deleted events purged (older than 30 days).");
  } catch (err) {
    console.error("Error purging old deleted events:", err);
  }
}

ensureUsersTable();
ensureCalendarEventsTable();
ensureFriendshipsTable();
ensureEventParticipantsTable();
purgeOldDeletedEvents();

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

async function getFriendIds(userId) {
  const [rows] = await database.query(
    `
    SELECT
      CASE
        WHEN requester_id = ? THEN addressee_id
        ELSE requester_id
      END AS friend_id
    FROM friendships
    WHERE (requester_id = ? OR addressee_id = ?)
      AND status = 'accepted'
    `,
    [userId, userId, userId]
  );

  return rows.map(r => r.friend_id);
}


app.get("/", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const [events] = await database.query(
      `
      SELECT DISTINCT ce.*
      FROM calendar_events ce
      LEFT JOIN event_participants ep ON ce.id = ep.event_id
      WHERE ce.deleted_at IS NULL
        AND (ce.user_id = ? OR ep.user_id = ?)
      ORDER BY ce.start_datetime ASC
      `,
      [userId, userId]
    );
    res.render("calendar", { events });
  } catch (err) {
    console.error("Error loading calendar:", err);
    res.redirect("/login");
  }
});


// Get events as JSON (for calendar display, including events user is invited to)
app.get("/api/events", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const [events] = await database.query(
      `
      SELECT DISTINCT ce.*
      FROM calendar_events ce
      LEFT JOIN event_participants ep ON ce.id = ep.event_id
      WHERE ce.deleted_at IS NULL
        AND (ce.user_id = ? OR ep.user_id = ?)
      ORDER BY ce.start_datetime ASC
      `,
      [userId, userId]
    );
    res.json(events);
  } catch (err) {
    console.error("Error fetching events:", err);
    res.status(500).json({ error: "Failed to fetch events" });
  }
});

// Create new event (with optional invited friends)
app.post("/api/events", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const {
      title,
      description,
      start_datetime,
      end_datetime,
      color,
      invited_user_ids
    } = req.body;

    if (!title || !start_datetime || !end_datetime) {
      return res.status(400).json({ error: "Title, start time, and end time are required" });
    }

    const [result] = await database.query(
      "INSERT INTO calendar_events (user_id, title, description, start_datetime, end_datetime, color) VALUES (?, ?, ?, ?, ?, ?)",
      [userId, title, description || null, start_datetime, end_datetime, color || '#3b82f6']
    );

    const eventId = result.insertId;

    // Always add owner as participant
    try {
      await database.query(
        "INSERT IGNORE INTO event_participants (event_id, user_id, role) VALUES (?, ?, 'owner')",
        [eventId, userId]
      );

      if (Array.isArray(invited_user_ids) && invited_user_ids.length > 0) {
        const friendIds = await getFriendIds(userId);
        const allowedSet = new Set(friendIds.map(Number));

        const uniqueInvited = [...new Set(invited_user_ids.map(Number))]
          .filter(id => allowedSet.has(id) && id !== userId);

        for (const invitedId of uniqueInvited) {
          await database.query(
            "INSERT IGNORE INTO event_participants (event_id, user_id, role) VALUES (?, ?, 'attendee')",
            [eventId, invitedId]
          );
        }
      }
    } catch (err) {
      console.error("Error inserting event participants:", err);
    }

    const [newEvent] = await database.query(
      "SELECT * FROM calendar_events WHERE id = ?",
      [eventId]
    );

    res.json(newEvent[0]);
  } catch (err) {
    console.error("Error creating event:", err);
    res.status(500).json({ error: "Failed to create event" });
  }
});



// Update event
app.put("/api/events/:id", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const eventId = req.params.id;
    const { title, description, start_datetime, end_datetime, color } = req.body;

    // Check if event belongs to user
    const [existing] = await database.query(
      "SELECT id FROM calendar_events WHERE id = ? AND user_id = ? AND deleted_at IS NULL",
      [eventId, userId]
    );

    if (!existing || existing.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }

    await database.query(
      "UPDATE calendar_events SET title = ?, description = ?, start_datetime = ?, end_datetime = ?, color = ? WHERE id = ? AND user_id = ?",
      [title, description, start_datetime, end_datetime, color, eventId, userId]
    );

    const [updatedEvent] = await database.query(
      "SELECT * FROM calendar_events WHERE id = ?",
      [eventId]
    );

    res.json(updatedEvent[0]);
  } catch (err) {
    console.error("Error updating event:", err);
    res.status(500).json({ error: "Failed to update event" });
  }
});

// Soft delete event
app.delete("/api/events/:id", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const eventId = req.params.id;

    // Get event + owner info
    const [rows] = await database.query(
      `SELECT ce.id, ce.user_id, u.username AS owner_username
       FROM calendar_events ce
       INNER JOIN users u ON ce.user_id = u.id
       WHERE ce.id = ? AND ce.deleted_at IS NULL`,
      [eventId]
    );

    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }

    const event = rows[0];

    if (event.user_id !== userId) {
      return res.status(403).json({
        error: `Only ${event.owner_username} can delete this event.`
      });
    }

    // Owner: perform soft delete
    const [result] = await database.query(
      "UPDATE calendar_events SET deleted_at = NOW() WHERE id = ? AND deleted_at IS NULL",
      [eventId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Event not found or already deleted" });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Error deleting event:", err);
    res.status(500).json({ error: "Failed to delete event" });
  }
});

// Trash page 
app.get("/events/deleted", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);

    await purgeOldDeletedEvents();

    const [deletedEvents] = await database.query(
      "SELECT * FROM calendar_events WHERE user_id = ? AND deleted_at IS NOT NULL ORDER BY deleted_at DESC",
      [userId]
    );

    res.render("deletedEvents", { events: deletedEvents });
  } catch (err) {
    console.error("Error loading deleted events:", err);
    res.redirect("/");
  }
});

// Restore a soft-deleted event, only if deleted less than 30 days ago
app.post("/api/events/:id/restore", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const eventId = req.params.id;

    const [rows] = await database.query(
      "SELECT deleted_at FROM calendar_events WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL",
      [eventId, userId]
    );

    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: "Deleted event not found" });
    }

    const deletedAt = new Date(rows[0].deleted_at);
    const limit = new Date();
    limit.setDate(limit.getDate() - 30); // 30 days ago

    if (deletedAt < limit) {
      return res.status(400).json({ error: "Event is too old to restore (older than 30 days)" });
    }

    await database.query(
      "UPDATE calendar_events SET deleted_at = NULL WHERE id = ? AND user_id = ?",
      [eventId, userId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Error restoring event:", err);
    res.status(500).json({ error: "Failed to restore event" });
  }
});

// Permanently delete a soft-deleted event if it's older than 30 days
app.delete("/api/events/:id/delete-forever", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const eventId = req.params.id;

    const [result] = await database.query(
      `
      DELETE FROM calendar_events
      WHERE id = ?
        AND user_id = ?
        AND deleted_at IS NOT NULL
        AND deleted_at < (NOW() - INTERVAL 30 DAY)
      `,
      [eventId, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(400).json({
        error: "Event cannot be permanently deleted yet. It must have been deleted for at least 30 days."
      });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Error permanently deleting event:", err);
    res.status(500).json({ error: "Failed to permanently delete event" });
  }
});


// Explicitly purge old deleted events (older than 30 days)
app.post("/api/events/purge-old", ensureLoggedIn, async (req, res) => {
  try {
    await purgeOldDeletedEvents();
    res.json({ success: true });
  } catch (err) {
    console.error("Error purging old events:", err);
    res.status(500).json({ error: "Failed to purge old events" });
  }
});

// Friends page
app.get("/friends", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    
    // Get accepted friends
    const [friends] = await database.query(`
      SELECT u.id, u.username, f.created_at
      FROM users u
      INNER JOIN friendships f ON (
        (f.requester_id = ? AND f.addressee_id = u.id) OR
        (f.addressee_id = ? AND f.requester_id = u.id)
      )
      WHERE f.status = 'accepted'
      ORDER BY u.username ASC
    `, [userId, userId]);

    // Get pending incoming requests
    const [pendingRequests] = await database.query(`
      SELECT u.id, u.username, f.id as friendship_id, f.created_at
      FROM users u
      INNER JOIN friendships f ON f.requester_id = u.id
      WHERE f.addressee_id = ? AND f.status = 'pending'
      ORDER BY f.created_at DESC
    `, [userId]);

    // Get pending outgoing requests
    const [sentRequests] = await database.query(`
      SELECT u.id, u.username, f.id as friendship_id, f.created_at
      FROM users u
      INNER JOIN friendships f ON f.addressee_id = u.id
      WHERE f.requester_id = ? AND f.status = 'pending'
      ORDER BY f.created_at DESC
    `, [userId]);

    res.render("friends", { friends, pendingRequests, sentRequests });
  } catch (err) {
    console.error("Error loading friends:", err);
    res.redirect("/");
  }
});

// Search users for friend requests
app.get("/api/users/search", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const query = req.query.q || '';
    
    if (query.length < 2) {
      return res.json([]);
    }

    const [users] = await database.query(`
      SELECT u.id, u.username
      FROM users u
      WHERE u.username LIKE ? AND u.id != ?
      AND NOT EXISTS (
        SELECT 1 FROM friendships f 
        WHERE ((f.requester_id = ? AND f.addressee_id = u.id) OR 
               (f.addressee_id = ? AND f.requester_id = u.id))
        AND f.status IN ('pending', 'accepted')
      )
      LIMIT 10
    `, [`%${query}%`, userId, userId, userId]);

    res.json(users);
  } catch (err) {
    console.error("Error searching users:", err);
    res.status(500).json({ error: "Failed to search users" });
  }
});

// Send friend request
app.post("/api/friends/request", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const { addressee_id } = req.body;

    if (!addressee_id || addressee_id == userId) {
      return res.status(400).json({ error: "Invalid user" });
    }

    // Check if friendship already exists
    const [existing] = await database.query(`
      SELECT id, status FROM friendships 
      WHERE (requester_id = ? AND addressee_id = ?) 
         OR (requester_id = ? AND addressee_id = ?)
    `, [userId, addressee_id, addressee_id, userId]);

    if (existing && existing.length > 0) {
      return res.status(400).json({ error: "Friend request already exists" });
    }

    await database.query(
      "INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?, ?, 'pending')",
      [userId, addressee_id]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Error sending friend request:", err);
    res.status(500).json({ error: "Failed to send friend request" });
  }
});

// Accept friend request
app.post("/api/friends/accept/:id", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const friendshipId = req.params.id;

    // Verify this request is for the current user
    const [friendship] = await database.query(
      "SELECT id FROM friendships WHERE id = ? AND addressee_id = ? AND status = 'pending'",
      [friendshipId, userId]
    );

    if (!friendship || friendship.length === 0) {
      return res.status(404).json({ error: "Friend request not found" });
    }

    await database.query(
      "UPDATE friendships SET status = 'accepted' WHERE id = ?",
      [friendshipId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Error accepting friend request:", err);
    res.status(500).json({ error: "Failed to accept friend request" });
  }
});

// Reject friend request
app.post("/api/friends/reject/:id", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const friendshipId = req.params.id;

    // Verify this request is for the current user
    const [friendship] = await database.query(
      "SELECT id FROM friendships WHERE id = ? AND addressee_id = ? AND status = 'pending'",
      [friendshipId, userId]
    );

    if (!friendship || friendship.length === 0) {
      return res.status(404).json({ error: "Friend request not found" });
    }

    await database.query(
      "DELETE FROM friendships WHERE id = ?",
      [friendshipId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Error rejecting friend request:", err);
    res.status(500).json({ error: "Failed to reject friend request" });
  }
});

// Remove friend
app.delete("/api/friends/:id", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const friendId = req.params.id;

    const [result] = await database.query(
      `DELETE FROM friendships 
       WHERE ((requester_id = ? AND addressee_id = ?) OR 
              (requester_id = ? AND addressee_id = ?))
       AND status = 'accepted'`,
      [userId, friendId, friendId, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Friendship not found" });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Error removing friend:", err);
    res.status(500).json({ error: "Failed to remove friend" });
  }
});

// Get list of accepted friends as JSON
app.get("/api/friends/list", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const friendIds = await getFriendIds(userId);

    if (friendIds.length === 0) {
      return res.json([]);
    }

    const placeholders = friendIds.map(() => "?").join(", ");
    const [rows] = await database.query(
      `SELECT id, username FROM users WHERE id IN (${placeholders}) ORDER BY username ASC`,
      friendIds
    );

    res.json(rows);
  } catch (err) {
    console.error("Error loading friends list:", err);
    res.status(500).json({ error: "Failed to load friends list" });
  }
});

// Find common free time slots between the current user and selected friends
app.post("/api/schedule/availability", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    let { user_ids, start_datetime, end_datetime, slot_minutes } = req.body;

    if (!start_datetime || !end_datetime) {
      return res.status(400).json({ error: "start_datetime and end_datetime are required" });
    }

    const start = new Date(start_datetime);
    const end = new Date(end_datetime);
    if (isNaN(start) || isNaN(end) || start >= end) {
      return res.status(400).json({ error: "Invalid date range" });
    }

    slot_minutes = Number(slot_minutes) || 60;
    if (slot_minutes <= 0) {
      return res.status(400).json({ error: "slot_minutes must be positive" });
    }

    if (!Array.isArray(user_ids)) {
      user_ids = [];
    }
    user_ids = user_ids.map(Number).filter(id => !isNaN(id));

    if (!user_ids.includes(userId)) {
      user_ids.push(userId);
    }

    const friendIds = await getFriendIds(userId);
    const allowedSet = new Set([userId, ...friendIds.map(Number)]);
    const uniqueUserIds = [...new Set(user_ids)].filter(id => allowedSet.has(id));

    if (uniqueUserIds.length === 0) {
      return res.status(400).json({ error: "No valid users to check availability for" });
    }

    // Load all events for these users that overlap the date range
    const placeholders = uniqueUserIds.map(() => "?").join(", ");
    const params = [...uniqueUserIds, start_datetime, end_datetime];

    const [rows] = await database.query(
      `
      SELECT user_id, start_datetime, end_datetime
      FROM calendar_events
      WHERE user_id IN (${placeholders})
        AND deleted_at IS NULL
        AND NOT (end_datetime <= ? OR start_datetime >= ?)
      `,
      params
    );

    // Convert busy intervals
    const busyIntervals = rows.map(r => ({
      start: new Date(r.start_datetime),
      end: new Date(r.end_datetime)
    }));

    const slotMs = slot_minutes * 60 * 1000;
    const freeSlots = [];

    for (let t = start.getTime(); t + slotMs <= end.getTime(); t += slotMs) {
      const slotStart = new Date(t);
      const slotEnd = new Date(t + slotMs);

      const isBusy = busyIntervals.some(interval => {
        return !(interval.end <= slotStart || interval.start >= slotEnd);
      });

      if (!isBusy) {
        freeSlots.push({
          start: slotStart.toISOString(),
          end: slotEnd.toISOString()
        });
      }
    }

    res.json({ slots: freeSlots });
  } catch (err) {
    console.error("Error finding common availability:", err);
    res.status(500).json({ error: "Failed to find common availability" });
  }
});


// Profile page
app.get("/profile", ensureLoggedIn, async (req, res) => {
  try {
    const userId = await getUserId(req);
    const [rows] = await database.query("SELECT * FROM users WHERE id = ?", [userId]);
    const user = rows[0];
    
    if (!user) return res.redirect("/");
    
    res.render("profile", { 
      user: user, 
      error: null, 
      success: null 
    });
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