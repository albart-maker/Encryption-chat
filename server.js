const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { createClient } = require('redis');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    maxHttpBufferSize: 1e8 // Allow uploads up to 100MB via Socket if needed
});

const PORT = 3000;
const SECRET_KEY = "super-secret-key-change-this-to-something-random";

// --- MIDDLEWARE ---
app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

// --- REDIS SETUP ---
const client = createClient();
client.on('error', (err) => console.log('Redis Client Error', err));

async function startServer() {
    await client.connect();
    console.log('✅ Connected to Redis Database');
    server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}
startServer();

// --- AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access Denied" });
    
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = user;
        next();
    });
};

// --- ROUTES: AUTHENTICATION (Zero-Knowledge Sync) ---

app.post('/api/register', async (req, res) => {
    // We expect 'encryptedPrivateKey' (The Locked Box) from the client
    const { username, password, publicKey, encryptedPrivateKey } = req.body;

    if (!username || !password || !publicKey || !encryptedPrivateKey) {
        return res.status(400).json({ error: "All fields are required" });
    }

    // Strong Password Enforcement
    const strongPasswordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
    if (!strongPasswordRegex.test(password)) {
        return res.status(400).json({ 
            error: "Password too weak. Must be 8+ chars, include a number & symbol." 
        });
    }

    const exists = await client.exists(`user:${username}`);
    if (exists) return res.status(400).json({ error: "Username taken" });

    const hashedPassword = await bcrypt.hash(password, 12);
    const userId = Date.now().toString();

    // Save User + The "Locked" Private Key
    await client.hSet(`user:${username}`, {
        id: userId,
        username: username,
        password: hashedPassword,
        public_key: publicKey,
        enc_priv_key: encryptedPrivateKey, // <--- SAVED HERE
        avatar: '👤'
    });

    await client.sAdd('all_users', username);
    res.json({ message: "Registered successfully" });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    const user = await client.hGetAll(`user:${username}`);
    
    if (!user.username || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ username: user.username, id: user.id }, SECRET_KEY);
    res.cookie('token', token, { httpOnly: true });

    // Send the Locked Key back so the browser can decrypt it
    res.json({ 
        message: "Success", 
        username: user.username, 
        id: user.id,
        enc_priv_key: user.enc_priv_key 
    });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: "Logged out" });
});

app.get('/api/me', authenticateToken, async (req, res) => {
    const user = await client.hGetAll(`user:${req.user.username}`);
    delete user.password;
    delete user.enc_priv_key; // Don't send this unless specifically asked
    res.json(user);
});

// --- ROUTES: ADMIN & DEBUG ---

// 1. Get List of Users
app.get('/api/admin/users', async (req, res) => {
    try {
        const allUsernames = await client.sMembers('all_users');
        const users = [];
        for (const username of allUsernames) {
            const id = await client.hGet(`user:${username}`, 'id');
            users.push({ id, username });
        }
        res.json(users);
    } catch (e) {
        res.status(500).json({ error: "Database error" });
    }
});

// 2. Delete User
app.delete('/api/admin/users/:username', async (req, res) => {
    try {
        const target = req.params.username;
        await client.sRem('all_users', target);
        await client.del(`user:${target}`);
        res.json({ message: "Deleted" });
    } catch (e) {
        res.status(500).json({ error: "Failed to delete" });
    }
});

// 3. DEBUG DUMP (This fixes your database.html issue)
app.get('/api/admin/dump', async (req, res) => {
    try {
        // Fetch Users
        const usernames = await client.sMembers('all_users');
        const users = [];
        for (const u of usernames) {
            const data = await client.hGetAll(`user:${u}`);
            users.push(data);
        }

        // Fetch Messages
        const messageKeys = await client.keys('messages:*');
        const messages = [];
        for (const key of messageKeys) {
            const rawMsgs = await client.lRange(key, 0, -1);
            messages.push({
                room: key,
                logs: rawMsgs.map(m => JSON.parse(m))
            });
        }

        res.json({ users, messages });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Failed to dump database" });
    }
});

// --- ROUTES: FRIENDS ---

app.get('/api/users/search', authenticateToken, async (req, res) => {
    const query = req.query.q ? req.query.q.toLowerCase() : "";
    const allUsers = await client.sMembers('all_users');
    const matches = [];

    for (const username of allUsers) {
        if (username.toLowerCase().includes(query) && username !== req.user.username) {
            const u = await client.hGetAll(`user:${username}`);
            matches.push({ id: u.id, username: u.username });
        }
    }
    res.json(matches);
});

app.post('/api/friends/request', authenticateToken, async (req, res) => {
    const { friendId } = req.body;
    const friendUsername = await findUsernameById(friendId);
    if (!friendUsername) return res.status(404).json({ error: "User not found" });

    await client.sAdd(`requests:${friendUsername}`, req.user.username);
    res.json({ msg: "Request sent" });
});

app.get('/api/friends/requests', authenticateToken, async (req, res) => {
    const requestNames = await client.sMembers(`requests:${req.user.username}`);
    const requests = [];
    for (const name of requestNames) {
        const u = await client.hGetAll(`user:${name}`);
        requests.push({ id: u.id, username: u.username });
    }
    res.json(requests);
});

app.post('/api/friends/accept', authenticateToken, async (req, res) => {
    const { requesterId } = req.body;
    const requesterUsername = await findUsernameById(requesterId);
    if (!requesterUsername) return res.status(404).json({ error: "User not found" });

    await client.sRem(`requests:${req.user.username}`, requesterUsername);
    await client.sAdd(`friends:${req.user.username}`, requesterUsername);
    await client.sAdd(`friends:${requesterUsername}`, req.user.username);

    res.json({ msg: "Accepted" });
});

app.post('/api/friends/remove', authenticateToken, async (req, res) => {
    const { friendId } = req.body;
    const friendUsername = await findUsernameById(friendId);
    if (!friendUsername) return res.status(404).json({ error: "User not found" });

    await client.sRem(`friends:${req.user.username}`, friendUsername);
    await client.sRem(`friends:${friendUsername}`, req.user.username);

    res.json({ message: "Removed" });
});

app.get('/api/friends', authenticateToken, async (req, res) => {
    const friendNames = await client.sMembers(`friends:${req.user.username}`);
    const friends = [];
    for (const name of friendNames) {
        const f = await client.hGetAll(`user:${name}`);
        friends.push({
            id: f.id,
            username: f.username,
            public_key: f.public_key 
        });
    }
    res.json(friends);
});

// --- ROUTES: UPLOADS & MESSAGES ---

const storage = multer.diskStorage({
    destination: 'uploads/',
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB

app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    res.json({ fileId: req.file.filename });
});

app.get('/api/download/:filename', (req, res) => {
    const filePath = path.join(__dirname, 'uploads', req.params.filename);
    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.status(404).send('File not found');
    }
});

app.get('/api/messages/:roomId', authenticateToken, async (req, res) => {
    const rawMessages = await client.lRange(`messages:${req.params.roomId}`, 0, -1);
    const messages = rawMessages.map(m => JSON.parse(m));
    res.json(messages);
});

// --- SOCKET.IO ---

io.use((socket, next) => {
    const cookie = socket.request.headers.cookie;
    if (!cookie) return next(new Error("Auth Error"));
    
    const token = cookie.split('; ').find(r => r.startsWith('token='))?.split('=')[1];
    if (!token) return next(new Error("Token missing"));

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (!err) { socket.user = user; next(); }
        else next(new Error("Invalid Token"));
    });
});

io.on('connection', (socket) => {
    socket.on('join-chat', async (friendId) => {
        const myId = await getUserId(socket.user.username);
        const ids = [String(myId), String(friendId)].sort();
        const roomId = `${ids[0]}-${ids[1]}`;

        socket.join(roomId);
        socket.emit('room-joined', roomId);
    });

    socket.on('chat-message', async (data) => {
        const myId = await getUserId(socket.user.username);
        
        const msgPayload = {
            room_id: data.roomId,
            sender_id: myId,
            sender: socket.user.username,
            content: data.data, // Encrypted content
            iv: data.iv,        // IV for content
            timestamp: new Date().toISOString()
        };

        // Save to Redis
        await client.rPush(`messages:${data.roomId}`, JSON.stringify(msgPayload));

        // Send to Friend (and not back to sender)
        socket.to(data.roomId).emit('receive-message', {
            ...msgPayload,
            roomId: data.roomId
        });
    });
});

// --- HELPERS ---

async function findUsernameById(id) {
    const allUsers = await client.sMembers('all_users');
    for (const u of allUsers) {
        const uid = await client.hGet(`user:${u}`, 'id');
        if (String(uid) === String(id)) return u;
    }
    return null;
}

async function getUserId(username) {
    return await client.hGet(`user:${username}`, 'id');
}
