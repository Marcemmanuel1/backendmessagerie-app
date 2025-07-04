require('dotenv').config();
const express = require("express");
const mysql = require("mysql2/promise");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const bcrypt = require("bcryptjs");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const http = require("http");
const socketio = require("socket.io");

const app = express();
const server = http.createServer(app);

// Configuration pour Render
const isProduction = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = isProduction 
  ? "https://nexuchat.onrender.com" 
  : "http://localhost:5173";

// Configuration de la base de données
const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "messagerie_app",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

if (isProduction) {
  dbConfig.ssl = {
    rejectUnauthorized: false
  };
}

const pool = mysql.createPool(dbConfig);
const sessionStore = new MySQLStore({}, pool);

// Middlewares
app.use(cors({ 
  origin: FRONTEND_URL,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Configuration des dossiers d'upload
const uploadsDir = path.join(__dirname, "uploads");
const avatarsDir = path.join(uploadsDir, "avatars");
const messagesDir = path.join(uploadsDir, "messages");

[uploadsDir, avatarsDir, messagesDir].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

app.use("/uploads/avatars", express.static(avatarsDir));
app.use("/uploads/messages", express.static(messagesDir));

// Configuration de Multer
const fileFilter = (req, file, cb) => {
  const allowedTypes = [
    'image/jpeg', 'image/png', 'image/gif',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation'
  ];
  
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("Type de fichier non autorisé"), false);
  }
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dest = file.fieldname === 'avatar' ? avatarsDir : messagesDir;
    cb(null, dest);
  },
  filename: (req, file, cb) => {
    const prefix = file.fieldname === 'avatar' ? 'avatar-' : 'msg-';
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, prefix + uniqueSuffix + path.extname(file.originalname));
  }
});

const uploadAvatar = multer({ 
  storage,
  fileFilter,
  limits: { fileSize: 25 * 1024 * 1024 }
});

const uploadMessageFile = multer({ 
  storage,
  fileFilter,
  limits: { fileSize: 25 * 1024 * 1024 }
});

// Configuration des sessions
app.use(
  session({
    name: "nexuchat.sid",
    secret: process.env.SESSION_SECRET || "votre_secret_tres_securise",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 1 semaine
    },
  })
);

// Middleware d'authentification
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: "Non authentifié" });
  }
  next();
};

// Configuration Socket.io
const io = socketio(server, {
  cors: {
    origin: FRONTEND_URL,
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Gestion des connexions Socket.io
const onlineUsers = new Map();

io.use((socket, next) => {
  session({
    name: "nexuchat.sid",
    secret: process.env.SESSION_SECRET || "votre_secret_tres_securise",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
  })(socket.request, {}, next);
});

io.on('connection', async (socket) => {
  const userId = socket.request.session.user?.id;
  if (!userId) return socket.disconnect(true);

  onlineUsers.set(userId, socket.id);
  
  try {
    await pool.query("UPDATE users SET status = 'En ligne' WHERE id = ?", [userId]);
    io.emit('user-status-changed', { userId, status: 'En ligne' });
  } catch (err) {
    console.error("Erreur mise à jour statut:", err);
  }

  socket.on('disconnect', async () => {
    onlineUsers.delete(userId);
    try {
      await pool.query("UPDATE users SET status = 'Hors ligne' WHERE id = ?", [userId]);
      io.emit('user-status-changed', { userId, status: 'Hors ligne' });
    } catch (err) {
      console.error("Erreur mise à jour statut:", err);
    }
  });

  // Gestion des messages
  socket.on('send-message', handleSendMessage);
  socket.on('mark-as-read', handleMarkAsRead);
});

// Fonctions de gestion Socket.io
async function handleSendMessage({ conversationId, content }, callback) {
  try {
    const socket = this;
    const userId = socket.request.session.user.id;
    
    const [conversation] = await pool.query(
      "SELECT user1_id, user2_id FROM conversations WHERE id = ?",
      [conversationId]
    );
    
    if (conversation.length === 0) {
      throw new Error("Conversation non trouvée");
    }

    const { user1_id, user2_id } = conversation[0];
    if (user1_id !== userId && user2_id !== userId) {
      throw new Error("Non autorisé");
    }

    const [result] = await pool.query(
      "INSERT INTO messages (conversation_id, sender_id, content) VALUES (?, ?, ?)",
      [conversationId, userId, content]
    );

    await pool.query(
      "UPDATE conversations SET last_message_id = ? WHERE id = ?",
      [result.insertId, conversationId]
    );

    const [message] = await pool.query(`
      SELECT m.id, m.content, m.created_at, m.sender_id, 
             u.name as sender_name, u.avatar as sender_avatar
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE m.id = ?
    `, [result.insertId]);

    const messageData = {
      ...message[0],
      conversationId,
      is_read: false
    };

    const otherUserId = user1_id === userId ? user2_id : user1_id;
    const recipientSocketId = onlineUsers.get(otherUserId);
    
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('new-message', messageData);
      messageData.is_read = true;
    }

    socket.emit('message-sent', messageData);
    updateConversationForUsers(userId, otherUserId, conversationId);

    callback({ success: true, message: messageData });
  } catch (err) {
    console.error("Erreur envoi message:", err);
    callback({ success: false, message: "Erreur lors de l'envoi du message" });
  }
}

async function handleMarkAsRead({ conversationId }) {
  try {
    const socket = this;
    const userId = socket.request.session.user.id;
    
    await pool.query(
      "UPDATE messages SET read_at = NOW() WHERE conversation_id = ? AND sender_id != ? AND read_at IS NULL",
      [conversationId, userId]
    );

    const [conversation] = await pool.query(`
      SELECT c.user1_id, c.user2_id 
      FROM conversations c
      WHERE c.id = ?
    `, [conversationId]);

    if (conversation.length > 0) {
      const { user1_id, user2_id } = conversation[0];
      const otherUserId = user1_id === userId ? user2_id : user1_id;
      
      updateConversationForUsers(userId, otherUserId, conversationId);
    }
  } catch (err) {
    console.error("Erreur marquage messages comme lus:", err);
  }
}

async function updateConversationForUsers(userId, otherUserId, conversationId) {
  try {
    const [conversation] = await pool.query(`
      SELECT c.id, 
             CASE 
               WHEN c.user1_id = ? THEN u2.id 
               ELSE u1.id 
             END as other_user_id,
             CASE 
               WHEN c.user1_id = ? THEN u2.name 
               ELSE u1.name 
             END as other_user_name,
             CASE 
               WHEN c.user1_id = ? THEN u2.avatar 
               ELSE u1.avatar 
             END as other_user_avatar,
             CASE 
               WHEN c.user1_id = ? THEN u2.status 
               ELSE u1.status 
             END as other_user_status,
             m.content as last_message,
             m.created_at as last_message_time,
             (SELECT COUNT(*) FROM messages WHERE conversation_id = c.id AND sender_id != ? AND read_at IS NULL) as unread_count
      FROM conversations c
      JOIN users u1 ON c.user1_id = u1.id
      JOIN users u2 ON c.user2_id = u2.id
      LEFT JOIN messages m ON c.last_message_id = m.id
      WHERE c.id = ?
    `, [userId, userId, userId, userId, userId, conversationId]);

    if (conversation.length > 0) {
      const convData = conversation[0];
      const senderSocketId = onlineUsers.get(userId);
      const recipientSocketId = onlineUsers.get(otherUserId);

      if (senderSocketId) {
        io.to(senderSocketId).emit('conversation-updated', convData);
      }
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('conversation-updated', {
          ...convData,
          unread_count: 0
        });
      }
    }
  } catch (err) {
    console.error("Erreur mise à jour conversation:", err);
  }
}

// Routes API
app.get("/api/check-auth", async (req, res) => {
  if (!req.session.user) {
    return res.json({ isAuthenticated: false });
  }

  try {
    const [rows] = await pool.query(
      "SELECT id, name, email, avatar, status FROM users WHERE id = ?", 
      [req.session.user.id]
    );
    
    if (rows.length === 0) {
      return res.json({ isAuthenticated: false });
    }

    const user = rows[0];
    req.session.user = { ...req.session.user, status: user.status };
    
    res.json({ 
      isAuthenticated: true, 
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        status: user.status
      }
    });
  } catch (err) {
    console.error("Erreur vérification auth:", err);
    res.json({ isAuthenticated: false });
  }
});

app.post("/api/register", uploadAvatar.single("avatar"), async (req, res) => {
  const { name, email, password } = req.body;
  
  if (!name || !email || !password) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).json({ 
      success: false, 
      message: "Tous les champs sont requis" 
    });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    
    const [existing] = await conn.query(
      "SELECT id FROM users WHERE email = ?", 
      [email]
    );
    
    if (existing.length > 0) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(409).json({ 
        success: false, 
        message: "Email déjà utilisé" 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const avatar = req.file 
      ? `/uploads/avatars/${req.file.filename}` 
      : "/uploads/avatars/default.jpg";

    await conn.query(
      `INSERT INTO users 
       (name, email, password, avatar, status, bio, phone, location) 
       VALUES (?, ?, ?, ?, 'Hors ligne', '', '', '')`, 
      [name, email, hashedPassword, avatar]
    );
    
    await conn.commit();
    res.status(201).json({ 
      success: true, 
      message: "Inscription réussie" 
    });
  } catch (err) {
    await conn.rollback();
    console.error("Erreur inscription:", err);
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(500).json({ 
      success: false, 
      message: "Erreur lors de l'inscription" 
    });
  } finally {
    conn.release();
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, message: "Email et mot de passe requis" });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length === 0) return res.status(401).json({ success: false, message: "Identifiants incorrects" });

    const user = rows[0];
    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(401).json({ success: false, message: "Identifiants incorrects" });

    await conn.query("UPDATE users SET status = 'En ligne' WHERE id = ?", [user.id]);
    req.session.user = { 
      id: user.id, 
      name: user.name, 
      email: user.email, 
      avatar: user.avatar, 
      status: "En ligne" 
    };
    await conn.commit();

    res.json({ 
      success: true, 
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        status: "En ligne"
      } 
    });
  } catch (err) {
    await conn.rollback();
    console.error("Erreur connexion:", err);
    res.status(500).json({ success: false, message: "Erreur lors de la connexion" });
  } finally {
    conn.release();
  }
});

app.post("/api/logout", requireAuth, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query("UPDATE users SET status = 'Hors ligne' WHERE id = ?", [req.session.user.id]);
    await conn.commit();

    req.session.destroy(err => {
      if (err) throw err;
      res.clearCookie("messagerie_session_cookie");
      res.json({ success: true, message: "Déconnexion réussie" });
    });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ success: false, message: "Erreur lors de la déconnexion" });
  } finally {
    conn.release();
  }
});

app.get("/api/users", requireAuth, async (req, res) => {
  try {
    const [users] = await pool.query(
      "SELECT id, name, avatar, status, bio, phone, location FROM users WHERE id != ? ORDER BY name ASC", 
      [req.session.user.id]
    );
    
    res.json({ success: true, users });
  } catch (err) {
    console.error("Erreur liste utilisateurs:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

app.get("/api/profile", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, name, email, avatar, status, bio, phone, location FROM users WHERE id = ?", 
      [req.session.user.id]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: "Utilisateur non trouvé" });
    }

    const user = rows[0];
    res.json({ success: true, user });
  } catch (err) {
    console.error("Erreur récupération profil:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

app.put("/api/profile", requireAuth, uploadAvatar.single("avatar"), async (req, res) => {
  const { name, bio, phone, location } = req.body;
  const userId = req.session.user.id;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    let avatar = req.session.user.avatar;
    if (req.file) {
      avatar = `/uploads/avatars/${req.file.filename}`;
      if (req.session.user.avatar !== "/uploads/avatars/default.jpg") {
        const oldAvatarPath = path.join(__dirname, req.session.user.avatar);
        if (fs.existsSync(oldAvatarPath)) fs.unlinkSync(oldAvatarPath);
      }
    }

    await conn.query(
      "UPDATE users SET name = ?, bio = ?, phone = ?, location = ?, avatar = ? WHERE id = ?",
      [name, bio, phone, location, avatar, userId]
    );

    req.session.user = {
      ...req.session.user,
      name,
      avatar
    };

    await conn.commit();
    res.json({ 
      success: true, 
      user: {
        id: userId,
        name,
        email: req.session.user.email,
        avatar,
        status: req.session.user.status,
        bio,
        phone,
        location
      } 
    });
  } catch (err) {
    await conn.rollback();
    console.error("Erreur mise à jour profil:", err);
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(500).json({ success: false, message: "Erreur lors de la mise à jour du profil" });
  } finally {
    conn.release();
  }
});

app.get("/api/conversations", requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    
    const [conversations] = await pool.query(`
      SELECT c.id, 
             CASE 
               WHEN c.user1_id = ? THEN u2.id 
               ELSE u1.id 
             END as other_user_id,
             CASE 
               WHEN c.user1_id = ? THEN u2.name 
               ELSE u1.name 
             END as other_user_name,
             CASE 
               WHEN c.user1_id = ? THEN u2.avatar 
               ELSE u1.avatar 
             END as other_user_avatar,
             CASE 
               WHEN c.user1_id = ? THEN u2.status 
               ELSE u1.status 
             END as other_user_status,
             m.content as last_message,
             m.created_at as last_message_time,
             (SELECT COUNT(*) FROM messages WHERE conversation_id = c.id AND sender_id != ? AND read_at IS NULL) as unread_count
      FROM conversations c
      JOIN users u1 ON c.user1_id = u1.id
      JOIN users u2 ON c.user2_id = u2.id
      LEFT JOIN messages m ON c.last_message_id = m.id
      WHERE c.user1_id = ? OR c.user2_id = ?
      ORDER BY m.created_at DESC
    `, [userId, userId, userId, userId, userId, userId, userId]);

    res.json({ success: true, conversations });
  } catch (err) {
    console.error("Erreur récupération conversations:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

app.get("/api/conversations/:otherUserId", requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const otherUserId = req.params.otherUserId;

    const [existing] = await pool.query(`
      SELECT id FROM conversations 
      WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
    `, [userId, otherUserId, otherUserId, userId]);

    if (existing.length > 0) {
      return res.json({ success: true, conversationId: existing[0].id });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [result] = await conn.query(
        "INSERT INTO conversations (user1_id, user2_id) VALUES (?, ?)",
        [userId, otherUserId]
      );
      await conn.commit();
      
      res.json({ success: true, conversationId: result.insertId });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Erreur récupération/conversation:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

app.get("/api/messages/:conversationId", requireAuth, async (req, res) => {
  try {
    const conversationId = req.params.conversationId;
    const userId = req.session.user.id;

    const [messages] = await pool.query(`
      SELECT m.id, m.content, m.created_at, m.sender_id, 
             u.name as sender_name, u.avatar as sender_avatar,
             m.read_at IS NOT NULL as is_read
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE m.conversation_id = ?
      ORDER BY m.created_at ASC
    `, [conversationId]);

    // Parser le contenu JSON pour les messages avec fichiers
    const parsedMessages = messages.map(msg => {
      try {
        const content = msg.content;
        if (content && content.startsWith('{') && content.endsWith('}')) {
          const fileData = JSON.parse(content);
          return {
            ...msg,
            content: null,
            fileUrl: fileData.fileUrl,
            fileType: fileData.fileType
          };
        }
        return msg;
      } catch (err) {
        return msg;
      }
    });

    // Marquer les messages comme lus
    await pool.query(
      "UPDATE messages SET read_at = NOW() WHERE conversation_id = ? AND sender_id != ? AND read_at IS NULL",
      [conversationId, userId]
    );

    res.json({ success: true, messages: parsedMessages });
  } catch (err) {
    console.error("Erreur récupération messages:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

app.post("/api/messages/upload", requireAuth, uploadMessageFile.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: "Aucun fichier fourni" });
  }

  const { conversationId } = req.body;
  const userId = req.session.user.id;
  const fileUrl = `/uploads/messages/${req.file.filename}`;
  const fileType = req.file.mimetype;

  // Stocker le chemin du fichier dans le contenu du message
  const content = JSON.stringify({ fileUrl, fileType });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Vérifier que l'utilisateur fait partie de la conversation
    const [conversation] = await conn.query(
      "SELECT user1_id, user2_id FROM conversations WHERE id = ? AND (user1_id = ? OR user2_id = ?)",
      [conversationId, userId, userId]
    );
    
    if (conversation.length === 0) {
      fs.unlinkSync(req.file.path);
      return res.status(403).json({ success: false, message: "Non autorisé" });
    }

    const { user1_id, user2_id } = conversation[0];
    const otherUserId = user1_id === userId ? user2_id : user1_id;

    // Insérer le message
    const [result] = await conn.query(
      "INSERT INTO messages (conversation_id, sender_id, content) VALUES (?, ?, ?)",
      [conversationId, userId, content]
    );

    // Mettre à jour la conversation avec le dernier message
    await conn.query(
      "UPDATE conversations SET last_message_id = ? WHERE id = ?",
      [result.insertId, conversationId]
    );

    // Récupérer les détails complets du message
    const [message] = await conn.query(`
      SELECT m.id, m.content, m.created_at, m.sender_id, 
             u.name as sender_name, u.avatar as sender_avatar,
             u.status as sender_status
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE m.id = ?
    `, [result.insertId]);

    await conn.commit();

    // Préparer les données du message pour l'émission
    const messageData = {
      ...message[0],
      content: null,
      fileUrl,
      fileType,
      conversationId,
      is_read: false
    };

    // Émettre le message via Socket.io
    const recipientSocketId = onlineUsers.get(otherUserId);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('new-message', messageData);
      messageData.is_read = true;
    }

    // Émettre aussi à l'expéditeur pour confirmation
    const senderSocketId = onlineUsers.get(userId);
    if (senderSocketId) {
      io.to(senderSocketId).emit('message-sent', messageData);
    }

    // Mettre à jour les conversations des deux utilisateurs
    const [updatedConv] = await conn.query(`
      SELECT c.id, 
             CASE 
               WHEN c.user1_id = ? THEN u2.id 
               ELSE u1.id 
             END as other_user_id,
             CASE 
               WHEN c.user1_id = ? THEN u2.name 
               ELSE u1.name 
             END as other_user_name,
             CASE 
               WHEN c.user1_id = ? THEN u2.avatar 
               ELSE u1.avatar 
             END as other_user_avatar,
             CASE 
               WHEN c.user1_id = ? THEN u2.status 
               ELSE u1.status 
             END as other_user_status,
             m.content as last_message,
             m.created_at as last_message_time,
             (SELECT COUNT(*) FROM messages WHERE conversation_id = c.id AND sender_id != ? AND read_at IS NULL) as unread_count
      FROM conversations c
      JOIN users u1 ON c.user1_id = u1.id
      JOIN users u2 ON c.user2_id = u2.id
      LEFT JOIN messages m ON c.last_message_id = m.id
      WHERE c.id = ?
    `, [userId, userId, userId, userId, userId, conversationId]);

    if (updatedConv.length > 0) {
      const conversationUpdate = updatedConv[0];
      
      // Émettre la mise à jour de la conversation aux deux utilisateurs
      if (senderSocketId) {
        io.to(senderSocketId).emit('conversation-updated', conversationUpdate);
      }
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('conversation-updated', {
          ...conversationUpdate,
          unread_count: recipientSocketId ? conversationUpdate.unread_count + 1 : 0
        });
      }
    }

    res.json({ 
      success: true, 
      message: messageData
    });
  } catch (err) {
    await conn.rollback();
    if (req.file) fs.unlinkSync(req.file.path);
    console.error("Erreur upload fichier:", err);
    res.status(500).json({ success: false, message: "Erreur lors de l'envoi du fichier" });
  } finally {
    conn.release();
  }
});
// Démarrer le serveur
server.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
  console.log(`Environnement: ${isProduction ? 'Production' : 'Développement'}`);
  console.log(`URL Frontend: ${FRONTEND_URL}`);
});

// Gestion des erreurs
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});