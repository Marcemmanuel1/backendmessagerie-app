require('dotenv').config();
const express = require("express");
const mysql = require("mysql2/promise");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const bcrypt = require("bcryptjs");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs").promises;
const http = require("http");
const socketio = require("socket.io");
const { v4: uuidv4 } = require("uuid");

// Initialisation de l'application
const app = express();
const server = http.createServer(app);

// Configuration Socket.io avec CORS
const io = socketio(server, {
  cors: {
    origin: process.env.CLIENT_URL || "https://nexuchat.onrender.com",
    methods: ["GET", "POST"],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000
});

// Configuration de la base de données
const dbConfig = {
  host: process.env.DB_HOST || "mysql-nexuchat.alwaysdata.net",
  user: process.env.DB_USER || "nexuchat",
  password: process.env.DB_PASSWORD || "Goldegelil@1",
  database: process.env.DB_NAME || "nexuchat_messagerieapp",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 10000
};

const pool = mysql.createPool(dbConfig);
const sessionStore = new MySQLStore({}, pool);

// Middlewares
app.use(cors({
  origin: process.env.CLIENT_URL || "https://nexuchat.onrender.com",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Configuration des dossiers d'upload
const configureDirectories = async () => {
  const uploadsDir = path.join(__dirname, "uploads");
  const avatarsDir = path.join(uploadsDir, "avatars");
  const messagesDir = path.join(uploadsDir, "messages");

  try {
    await fs.mkdir(uploadsDir, { recursive: true });
    await fs.mkdir(avatarsDir, { recursive: true });
    await fs.mkdir(messagesDir, { recursive: true });
  } catch (err) {
    console.error("Erreur création des dossiers:", err);
  }
};

// Configuration de Multer
const storageConfig = {
  avatars: multer.diskStorage({
    destination: (req, file, cb) => cb(null, path.join(__dirname, "uploads/avatars")),
    filename: (req, file, cb) => cb(null, `avatar-${uuidv4()}${path.extname(file.originalname)}`)
  }),
  messages: multer.diskStorage({
    destination: (req, file, cb) => cb(null, path.join(__dirname, "uploads/messages")),
    filename: (req, file, cb) => cb(null, `msg-${uuidv4()}${path.extname(file.originalname)}`)
  })
};

const fileFilter = (req, file, cb) => {
  const allowedTypes = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
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

const uploadAvatar = multer({
  storage: storageConfig.avatars,
  fileFilter,
  limits: { fileSize: 25 * 1024 * 1024 }
});

const uploadMessageFile = multer({
  storage: storageConfig.messages,
  fileFilter,
  limits: { fileSize: 25 * 1024 * 1024 }
});

// Configuration de la session
app.use(session({
  key: "messagerie_session_cookie",
  secret: process.env.SESSION_SECRET || "une_cle_secrete_complexe_et_longue",
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Middleware d'authentification
const requireAuth = async (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: "Non authentifié" });
  }

  try {
    const [rows] = await pool.query(
      "SELECT id FROM users WHERE id = ?",
      [req.session.user.id]
    );
    
    if (rows.length === 0) {
      req.session.destroy();
      return res.status(401).json({ success: false, message: "Session invalide" });
    }
    
    next();
  } catch (err) {
    console.error("Erreur vérification auth:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
};

// Gestion des connexions Socket.io
const onlineUsers = new Map();

io.use((socket, next) => {
  session({
    key: "messagerie_session_cookie",
    secret: process.env.SESSION_SECRET || "une_cle_secrete_complexe_et_longue",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
  })(socket.request, {}, (err) => {
    if (err) return next(err);
    
    if (!socket.request.session || !socket.request.session.user) {
      return next(new Error('Non authentifié'));
    }
    
    next();
  });
});

const setupSocketIO = () => {
  io.on('connection', async (socket) => {
    const userId = socket.request.session.user?.id;
    if (!userId) return socket.disconnect(true);

    console.log(`Nouvelle connexion Socket.io - User ID: ${userId}`);

    // Gestion des connexions multiples
    const existingSocketId = onlineUsers.get(userId);
    if (existingSocketId) {
      const existingSocket = io.sockets.sockets.get(existingSocketId);
      if (existingSocket) {
        existingSocket.disconnect(true);
      }
    }

    onlineUsers.set(userId, socket.id);

    try {
      await pool.query("UPDATE users SET status = 'En ligne' WHERE id = ?", [userId]);
      io.emit('user-status-changed', { userId, status: 'En ligne' });
    } catch (err) {
      console.error("Erreur mise à jour statut en ligne:", err);
    }

    // Gestion des déconnexions
    socket.on('disconnect', async (reason) => {
      console.log(`Déconnexion - User ID: ${userId}, Raison: ${reason}`);

      // Vérifier si c'est la dernière connexion de cet utilisateur
      if (onlineUsers.get(userId) === socket.id) {
        onlineUsers.delete(userId);

        try {
          await pool.query("UPDATE users SET status = 'Hors ligne' WHERE id = ?", [userId]);
          io.emit('user-status-changed', { userId, status: 'Hors ligne' });
        } catch (err) {
          console.error("Erreur mise à jour statut hors ligne:", err);
        }
      }
    });

    // Gestion des messages
    socket.on('send-message', async ({ conversationId, content }, callback) => {
      try {
        const conn = await pool.getConnection();
        await conn.beginTransaction();

        // Vérification de la conversation
        const [conversation] = await conn.query(
          "SELECT user1_id, user2_id FROM conversations WHERE id = ?",
          [conversationId]
        );
        
        if (conversation.length === 0) {
          await conn.rollback();
          return callback({ success: false, message: "Conversation non trouvée" });
        }

        const { user1_id, user2_id } = conversation[0];
        if (user1_id !== userId && user2_id !== userId) {
          await conn.rollback();
          return callback({ success: false, message: "Non autorisé" });
        }

        // Insertion du message
        const [result] = await conn.query(
          "INSERT INTO messages (conversation_id, sender_id, content) VALUES (?, ?, ?)",
          [conversationId, userId, content]
        );

        // Mise à jour de la conversation
        await conn.query(
          "UPDATE conversations SET last_message_id = ?, updated_at = NOW() WHERE id = ?",
          [result.insertId, conversationId]
        );

        // Récupération des détails du message
        const [message] = await conn.query(`
          SELECT m.id, m.content, m.created_at, m.sender_id, 
                 u.name as sender_name, u.avatar as sender_avatar
          FROM messages m
          JOIN users u ON m.sender_id = u.id
          WHERE m.id = ?
        `, [result.insertId]);

        await conn.commit();

        // Préparation des données du message
        const messageData = {
          ...message[0],
          conversationId,
          is_read: false
        };

        // Émission du message
        const otherUserId = user1_id === userId ? user2_id : user1_id;
        const recipientSocketId = onlineUsers.get(otherUserId);
        
        if (recipientSocketId) {
          io.to(recipientSocketId).emit('new-message', messageData);
        }

        // Confirmation à l'expéditeur
        socket.emit('message-sent', {
          ...messageData,
          is_read: !!recipientSocketId
        });

        // Mise à jour des conversations
        await updateConversationForUsers(conn, conversationId, userId, otherUserId);

        callback({ success: true, message: messageData });
      } catch (err) {
        console.error("Erreur envoi message:", err);
        callback({ success: false, message: "Erreur lors de l'envoi du message" });
      }
    });

    // Marquer les messages comme lus
    socket.on('mark-as-read', async ({ conversationId }) => {
      try {
        await pool.query(
          "UPDATE messages SET read_at = NOW() WHERE conversation_id = ? AND sender_id != ? AND read_at IS NULL",
          [conversationId, userId]
        );

        // Mise à jour de la conversation
        const [conversation] = await pool.query(
          "SELECT user1_id, user2_id FROM conversations WHERE id = ?",
          [conversationId]
        );

        if (conversation.length > 0) {
          const { user1_id, user2_id } = conversation[0];
          const otherUserId = user1_id === userId ? user2_id : user1_id;
          
          // Informer l'autre utilisateur
          const recipientSocketId = onlineUsers.get(otherUserId);
          if (recipientSocketId) {
            io.to(recipientSocketId).emit('messages-read', { conversationId });
          }
        }
      } catch (err) {
        console.error("Erreur marquage messages comme lus:", err);
      }
    });
  });
};

// Fonction utilitaire pour mettre à jour les conversations
const updateConversationForUsers = async (conn, conversationId, userId, otherUserId) => {
  const [conversation] = await conn.query(`
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
    const recipientSocketId = onlineUsers.get(otherUserId);
    
    // Émettre à l'utilisateur actuel
    io.to(onlineUsers.get(userId)).emit('conversation-updated', convData);
    
    // Émettre à l'autre utilisateur avec un unread_count incrémenté
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('conversation-updated', {
        ...convData,
        unread_count: convData.unread_count + 1
      });
    }
  }
};

// Routes API
const setupRoutes = () => {
  // Vérification d'authentification
  app.get("/api/check-auth", async (req, res) => {
    try {
      if (!req.session.user) {
        return res.json({ isAuthenticated: false });
      }

      const [rows] = await pool.query(
        "SELECT id, name, email, avatar, status FROM users WHERE id = ?",
        [req.session.user.id]
      );
      
      if (rows.length === 0) {
        req.session.destroy();
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

  // Inscription
  app.post("/api/register", uploadAvatar.single("avatar"), async (req, res) => {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      if (req.file) await fs.unlink(req.file.path);
      return res.status(400).json({ 
        success: false, 
        message: "Tous les champs sont requis" 
      });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      
      // Vérification de l'email existant
      const [existing] = await conn.query(
        "SELECT id FROM users WHERE email = ?", 
        [email]
      );
      
      if (existing.length > 0) {
        if (req.file) await fs.unlink(req.file.path);
        return res.status(409).json({ 
          success: false, 
          message: "Email déjà utilisé" 
        });
      }

      // Hash du mot de passe
      const hashedPassword = await bcrypt.hash(password, 12);
      const avatar = req.file ? `/uploads/avatars/${req.file.filename}` : null;

      // Création de l'utilisateur
      const [result] = await conn.query(
        `INSERT INTO users 
         (name, email, password, avatar, status, bio, phone, location) 
         VALUES (?, ?, ?, ?, 'Hors ligne', '', '', '')`, 
        [name, email, hashedPassword, avatar]
      );

      await conn.commit();
      
      res.status(201).json({ 
        success: true, 
        message: "Inscription réussie",
        userId: result.insertId
      });
    } catch (err) {
      await conn.rollback();
      console.error("Erreur inscription:", err);
      if (req.file) await fs.unlink(req.file.path);
      res.status(500).json({ 
        success: false, 
        message: "Erreur lors de l'inscription" 
      });
    } finally {
      conn.release();
    }
  });

  // Connexion
  app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: "Email et mot de passe requis" 
      });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      
      const [rows] = await conn.query(
        "SELECT * FROM users WHERE email = ?", 
        [email]
      );
      
      if (rows.length === 0) {
        return res.status(401).json({ 
          success: false, 
          message: "Identifiants incorrects" 
        });
      }

      const user = rows[0];
      const validPass = await bcrypt.compare(password, user.password);
      
      if (!validPass) {
        return res.status(401).json({ 
          success: false, 
          message: "Identifiants incorrects" 
        });
      }

      // Mise à jour du statut
      await conn.query(
        "UPDATE users SET status = 'En ligne' WHERE id = ?", 
        [user.id]
      );

      // Création de la session
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
      res.status(500).json({ 
        success: false, 
        message: "Erreur lors de la connexion" 
      });
    } finally {
      conn.release();
    }
  });

  // Déconnexion
  app.post("/api/logout", requireAuth, async (req, res) => {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      
      await conn.query(
        "UPDATE users SET status = 'Hors ligne' WHERE id = ?", 
        [req.session.user.id]
      );

      await conn.commit();
      
      req.session.destroy(err => {
        if (err) {
          console.error("Erreur destruction session:", err);
          return res.status(500).json({ 
            success: false, 
            message: "Erreur lors de la déconnexion" 
          });
        }
        
        res.clearCookie("messagerie_session_cookie");
        res.json({ 
          success: true, 
          message: "Déconnexion réussie" 
        });
      });
    } catch (err) {
      await conn.rollback();
      console.error("Erreur déconnexion:", err);
      res.status(500).json({ 
        success: false, 
        message: "Erreur lors de la déconnexion" 
      });
    } finally {
      conn.release();
    }
  });

  // Récupération des utilisateurs
  app.get("/api/users", requireAuth, async (req, res) => {
    try {
      const [users] = await pool.query(
        `SELECT id, name, avatar, status, bio, phone, location 
         FROM users 
         WHERE id != ? 
         ORDER BY name ASC`, 
        [req.session.user.id]
      );
      
      res.json({ success: true, users });
    } catch (err) {
      console.error("Erreur liste utilisateurs:", err);
      res.status(500).json({ 
        success: false, 
        message: "Erreur serveur" 
      });
    }
  });

  // Récupération du profil
  app.get("/api/profile", requireAuth, async (req, res) => {
    try {
      const [rows] = await pool.query(
        `SELECT id, name, email, avatar, status, bio, phone, location 
         FROM users 
         WHERE id = ?`, 
        [req.session.user.id]
      );
      
      if (rows.length === 0) {
        return res.status(404).json({ 
          success: false, 
          message: "Utilisateur non trouvé" 
        });
      }

      res.json({ success: true, user: rows[0] });
    } catch (err) {
      console.error("Erreur récupération profil:", err);
      res.status(500).json({ 
        success: false, 
        message: "Erreur serveur" 
      });
    }
  });

  // Mise à jour du profil
  app.put("/api/profile", requireAuth, uploadAvatar.single("avatar"), async (req, res) => {
    const { name, bio, phone, location } = req.body;
    const userId = req.session.user.id;

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      let avatar = req.session.user.avatar;
      
      // Gestion de la nouvelle image
      if (req.file) {
        avatar = `/uploads/avatars/${req.file.filename}`;
        
        // Suppression de l'ancienne image si ce n'est pas l'image par défaut
        if (req.session.user.avatar && !req.session.user.avatar.includes('default.jpg')) {
          try {
            await fs.unlink(path.join(__dirname, req.session.user.avatar));
          } catch (err) {
            console.error("Erreur suppression ancien avatar:", err);
          }
        }
      }

      // Mise à jour en base
      await conn.query(
        `UPDATE users 
         SET name = ?, bio = ?, phone = ?, location = ?, avatar = ? 
         WHERE id = ?`,
        [name, bio, phone, location, avatar, userId]
      );

      // Mise à jour de la session
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
      if (req.file) await fs.unlink(req.file.path);
      res.status(500).json({ 
        success: false, 
        message: "Erreur lors de la mise à jour du profil" 
      });
    } finally {
      conn.release();
    }
  });

  // Récupération des conversations
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
        ORDER BY COALESCE(m.created_at, c.created_at) DESC
      `, [userId, userId, userId, userId, userId, userId, userId]);

      res.json({ success: true, conversations });
    } catch (err) {
      console.error("Erreur récupération conversations:", err);
      res.status(500).json({ 
        success: false, 
        message: "Erreur serveur" 
      });
    }
  });

  // Récupération ou création d'une conversation
  app.get("/api/conversations/:otherUserId", requireAuth, async (req, res) => {
    try {
      const userId = req.session.user.id;
      const otherUserId = req.params.otherUserId;

      // Vérification de l'existence de la conversation
      const [existing] = await pool.query(`
        SELECT id FROM conversations 
        WHERE (user1_id = ? AND user2_id = ?) 
           OR (user1_id = ? AND user2_id = ?)
      `, [userId, otherUserId, otherUserId, userId]);

      if (existing.length > 0) {
        return res.json({ 
          success: true, 
          conversationId: existing[0].id 
        });
      }

      // Création d'une nouvelle conversation
      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        
        const [result] = await conn.query(
          "INSERT INTO conversations (user1_id, user2_id) VALUES (?, ?)",
          [userId, otherUserId]
        );
        
        await conn.commit();
        
        res.json({ 
          success: true, 
          conversationId: result.insertId 
        });
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }
    } catch (err) {
      console.error("Erreur récupération/conversation:", err);
      res.status(500).json({ 
        success: false, 
        message: "Erreur serveur" 
      });
    }
  });

  // Récupération des messages d'une conversation
  app.get("/api/messages/:conversationId", requireAuth, async (req, res) => {
    try {
      const conversationId = req.params.conversationId;
      const userId = req.session.user.id;

      // Vérification que l'utilisateur fait partie de la conversation
      const [conversation] = await pool.query(
        "SELECT id FROM conversations WHERE id = ? AND (user1_id = ? OR user2_id = ?)",
        [conversationId, userId, userId]
      );
      
      if (conversation.length === 0) {
        return res.status(403).json({ 
          success: false, 
          message: "Non autorisé" 
        });
      }

      // Récupération des messages
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
          if (msg.content && msg.content.startsWith('{') && msg.content.endsWith('}')) {
            const fileData = JSON.parse(msg.content);
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

      res.json({ 
        success: true, 
        messages: parsedMessages 
      });
    } catch (err) {
      console.error("Erreur récupération messages:", err);
      res.status(500).json({ 
        success: false, 
        message: "Erreur serveur" 
      });
    }
  });

  // Upload de fichier pour un message
  app.post("/api/messages/upload", requireAuth, uploadMessageFile.single("file"), async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ 
        success: false, 
        message: "Aucun fichier fourni" 
      });
    }

    const { conversationId } = req.body;
    const userId = req.session.user.id;
    const fileUrl = `/uploads/messages/${req.file.filename}`;
    const fileType = req.file.mimetype;

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Vérification de la conversation
      const [conversation] = await conn.query(
        "SELECT user1_id, user2_id FROM conversations WHERE id = ? AND (user1_id = ? OR user2_id = ?)",
        [conversationId, userId, userId]
      );
      
      if (conversation.length === 0) {
        await fs.unlink(req.file.path);
        return res.status(403).json({ 
          success: false, 
          message: "Non autorisé" 
        });
      }

      const { user1_id, user2_id } = conversation[0];
      const otherUserId = user1_id === userId ? user2_id : user1_id;

      // Insertion du message
      const content = JSON.stringify({ fileUrl, fileType });
      const [result] = await conn.query(
        "INSERT INTO messages (conversation_id, sender_id, content) VALUES (?, ?, ?)",
        [conversationId, userId, content]
      );

      // Mise à jour de la conversation
      await conn.query(
        "UPDATE conversations SET last_message_id = ?, updated_at = NOW() WHERE id = ?",
        [result.insertId, conversationId]
      );

      // Récupération des détails du message
      const [message] = await conn.query(`
        SELECT m.id, m.content, m.created_at, m.sender_id, 
               u.name as sender_name, u.avatar as sender_avatar,
               u.status as sender_status
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.id = ?
      `, [result.insertId]);

      await conn.commit();

      // Préparation des données du message
      const messageData = {
        ...message[0],
        content: null,
        fileUrl,
        fileType,
        conversationId,
        is_read: false
      };

      // Émission via Socket.io
      const recipientSocketId = onlineUsers.get(otherUserId);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('new-message', messageData);
        messageData.is_read = true;
      }

      const senderSocketId = onlineUsers.get(userId);
      if (senderSocketId) {
        io.to(senderSocketId).emit('message-sent', messageData);
      }

      // Mise à jour des conversations
      await updateConversationForUsers(conn, conversationId, userId, otherUserId);

      res.json({ 
        success: true, 
        message: messageData 
      });
    } catch (err) {
      await conn.rollback();
      if (req.file) await fs.unlink(req.file.path);
      console.error("Erreur upload fichier:", err);
      res.status(500).json({ 
        success: false, 
        message: "Erreur lors de l'envoi du fichier" 
      });
    } finally {
      conn.release();
    }
  });
};

// Initialisation du serveur
const startServer = async () => {
  await configureDirectories();
  setupRoutes();
  setupSocketIO();

  server.listen(process.env.PORT || 5000, () => {
    console.log(`Serveur démarré sur le port ${process.env.PORT || 5000}`);
  });
};

// Gestion des erreurs globales
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

// Démarrer le serveur
startServer().catch(err => {
  console.error("Erreur démarrage serveur:", err);
  process.exit(1);
});
