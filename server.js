require('dotenv').config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs").promises;
const http = require("http");
const socketio = require("socket.io");
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");

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

// Middlewares
app.use(cors({
  origin: process.env.CLIENT_URL || "https://nexuchat.onrender.com",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Configuration JWT
const JWT_SECRET = process.env.JWT_SECRET || "une_cle_secrete_complexe_et_longue";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1d";

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

// Middleware d'authentification JWT
const requireAuth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: "Token manquant" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Vérification que l'utilisateur existe toujours
    const [rows] = await pool.query(
      "SELECT id FROM users WHERE id = ?",
      [decoded.userId]
    );
    
    if (rows.length === 0) {
      return res.status(401).json({ success: false, message: "Utilisateur non trouvé" });
    }
    
    req.userId = decoded.userId;
    next();
  } catch (err) {
    console.error("Erreur vérification token:", err);
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: "Token expiré" });
    }
    res.status(401).json({ success: false, message: "Token invalide" });
  }
};

// Gestion des connexions Socket.io
const onlineUsers = new Map();
const userSockets = new Map();

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  
  if (!token) {
    return next(new Error('Authentification requise'));
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return next(new Error('Authentification invalide'));
    }
    
    socket.userId = decoded.userId;
    next();
  });
});

const setupSocketIO = () => {
  io.on('connection', async (socket) => {
    const userId = socket.userId;
    if (!userId) return socket.disconnect(true);

    console.log(`Nouvelle connexion Socket.io - User ID: ${userId}`);

    // Gestion des connexions multiples
    if (!userSockets.has(userId)) {
      userSockets.set(userId, new Set());
    }
    userSockets.get(userId).add(socket.id);
    
    // Mise à jour de la liste des utilisateurs en ligne
    if (!onlineUsers.has(userId)) {
      onlineUsers.set(userId, socket.id);
      
      try {
        await pool.query("UPDATE users SET status = 'En ligne' WHERE id = ?", [userId]);
        io.emit('user-status-changed', { userId, status: 'En ligne' });
      } catch (err) {
        console.error("Erreur mise à jour statut en ligne:", err);
      }
    }

    // Gestion des déconnexions
    socket.on('disconnect', async (reason) => {
      console.log(`Déconnexion - User ID: ${userId}, Raison: ${reason}`);

      if (userSockets.has(userId)) {
        const sockets = userSockets.get(userId);
        sockets.delete(socket.id);
        
        if (sockets.size === 0) {
          userSockets.delete(userId);
          onlineUsers.delete(userId);

          try {
            await pool.query("UPDATE users SET status = 'Hors ligne' WHERE id = ?", [userId]);
            io.emit('user-status-changed', { userId, status: 'Hors ligne' });
          } catch (err) {
            console.error("Erreur mise à jour statut hors ligne:", err);
          }
        }
      }
    });

    // Rejoindre les rooms des conversations
    socket.on('join-conversations', async () => {
      try {
        const [conversations] = await pool.query(
          "SELECT id FROM conversations WHERE user1_id = ? OR user2_id = ?",
          [userId, userId]
        );
        
        conversations.forEach(conv => {
          socket.join(`conversation_${conv.id}`);
        });
      } catch (err) {
        console.error("Erreur rejoindre conversations:", err);
      }
    });

    // Gestion des messages
    socket.on('send-message', async ({ conversationId, content }, callback) => {
      let conn;
      try {
        conn = await pool.getConnection();
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
          conversationId,
          is_read: false
        };

        // Émission du message
        io.to(`conversation_${conversationId}`).emit('new-message', messageData);

        // Mise à jour des conversations
        const otherUserId = user1_id === userId ? user2_id : user1_id;
        await updateConversationForUsers(conn, conversationId, userId, otherUserId);

        callback({ success: true, message: messageData });
      } catch (err) {
        console.error("Erreur envoi message:", err);
        if (conn) await conn.rollback();
        callback({ success: false, message: "Erreur lors de l'envoi du message" });
      } finally {
        if (conn) conn.release();
      }
    });

    // Marquer les messages comme lus
    socket.on('mark-as-read', async ({ conversationId }) => {
      try {
        await pool.query(
          "UPDATE messages SET read_at = NOW() WHERE conversation_id = ? AND sender_id != ? AND read_at IS NULL",
          [conversationId, userId]
        );

        io.to(`conversation_${conversationId}`).emit('messages-read', { conversationId });
      } catch (err) {
        console.error("Erreur marquage messages comme lus:", err);
      }
    });
  });
};

// Fonction utilitaire pour mettre à jour les conversations
const updateConversationForUsers = async (conn, conversationId, userId, otherUserId) => {
  try {
    // Récupération des données de conversation pour l'utilisateur actuel
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
      
      // Émettre à l'utilisateur actuel
      if (userSockets.has(userId)) {
        userSockets.get(userId).forEach(socketId => {
          io.to(socketId).emit('conversation-updated', convData);
        });
      }
      
      // Émettre à l'autre utilisateur
      if (userSockets.has(otherUserId)) {
        userSockets.get(otherUserId).forEach(socketId => {
          io.to(socketId).emit('conversation-updated', {
            ...convData,
            unread_count: convData.unread_count + 1
          });
        });
      }
    }
  } catch (err) {
    console.error("Erreur mise à jour conversation:", err);
  }
};

// Fonction pour générer un token JWT
const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

// Routes API
const setupRoutes = () => {
  // Vérification d'authentification
  app.get("/api/check-auth", requireAuth, async (req, res) => {
    try {
      const [rows] = await pool.query(
        "SELECT id, name, email, avatar, status FROM users WHERE id = ?",
        [req.userId]
      );
      
      if (rows.length === 0) {
        return res.status(404).json({ isAuthenticated: false });
      }

      const user = rows[0];
      
      res.json({ 
        isAuthenticated: true, 
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          avatar: user.avatar,
          status: user.status
        },
        token: generateToken(user.id)
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

      const userId = result.insertId;
      const token = generateToken(userId);

      await conn.commit();
      
      res.status(201).json({ 
        success: true, 
        message: "Inscription réussie",
        userId,
        token,
        user: {
          id: userId,
          name,
          email,
          avatar,
          status: 'Hors ligne'
        }
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

      // Génération du token JWT
      const token = generateToken(user.id);

      await conn.commit();
      
      res.json({ 
        success: true, 
        token,
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
        [req.userId]
      );

      await conn.commit();
      
      res.json({ 
        success: true, 
        message: "Déconnexion réussie" 
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
        [req.userId]
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
        [req.userId]
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
    const userId = req.userId;

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Récupération de l'utilisateur actuel
      const [currentUser] = await conn.query(
        "SELECT avatar FROM users WHERE id = ?",
        [userId]
      );
      
      if (currentUser.length === 0) {
        return res.status(404).json({ 
          success: false, 
          message: "Utilisateur non trouvé" 
        });
      }

      let avatar = currentUser[0].avatar;
      
      // Gestion de la nouvelle image
      if (req.file) {
        avatar = `/uploads/avatars/${req.file.filename}`;
        
        // Suppression de l'ancienne image si ce n'est pas l'image par défaut
        if (currentUser[0].avatar && !currentUser[0].avatar.includes('default.jpg')) {
          try {
            await fs.unlink(path.join(__dirname, currentUser[0].avatar));
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

      await conn.commit();
      
      // Récupération des données mises à jour
      const [updatedUser] = await conn.query(
        "SELECT id, name, email, avatar, status, bio, phone, location FROM users WHERE id = ?",
        [userId]
      );

      res.json({ 
        success: true, 
        user: updatedUser[0],
        token: generateToken(userId) // Renvoie un nouveau token avec les données mises à jour
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
      const userId = req.userId;
      
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
      const userId = req.userId;
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
        
        const conversationId = result.insertId;

        // Récupération des détails de la conversation
        const [newConversation] = await conn.query(`
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
                 NULL as last_message,
                 NULL as last_message_time,
                 0 as unread_count
          FROM conversations c
          JOIN users u1 ON c.user1_id = u1.id
          JOIN users u2 ON c.user2_id = u2.id
          WHERE c.id = ?
        `, [userId, userId, userId, userId, conversationId]);

        await conn.commit();

        // Notifier les deux utilisateurs de la nouvelle conversation
        if (userSockets.has(userId)) {
          userSockets.get(userId).forEach(socketId => {
            io.to(socketId).emit('new-conversation', newConversation[0]);
          });
        }

        if (userSockets.has(otherUserId)) {
          userSockets.get(otherUserId).forEach(socketId => {
            io.to(socketId).emit('new-conversation', {
              ...newConversation[0],
              other_user_id: userId,
              other_user_name: newConversation[0].other_user_name, // À ajuster selon la logique
              other_user_avatar: newConversation[0].other_user_avatar // À ajuster selon la logique
            });
          });
        }
        
        res.json({ 
          success: true, 
          conversationId,
          conversation: newConversation[0]
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
      const userId = req.userId;

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
    const userId = req.userId;
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

      // Émission via Socket.io à la room de conversation
      io.to(`conversation_${conversationId}`).emit('new-message', messageData);

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