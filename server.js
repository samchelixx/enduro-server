const express = require('express');
const cors = require('cors');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'enduro-secret-key-123';
const DB_FILE = './enduro_db.json';

const GIST_TOKEN = process.env.GIST_TOKEN;
const GIST_ID = process.env.GIST_ID;

app.use(cors());
app.use(express.json({ limit: '50mb' }));

let db = { users: [], map_data: {}, friends: [], shared_routes: {} };

// Обертка для fetch, чтобы работал в Node 20
async function syncFromGist() {
    if (!GIST_TOKEN || !GIST_ID) return;
    try {
        const res = await fetch(`https://api.github.com/gists/${GIST_ID}`, {
            headers: { 'Authorization': `token ${GIST_TOKEN}` }
        });
        if (!res.ok) throw new Error('Gist fetch failed');
        const data = await res.json();
        const content = data.files['enduro_db.json']?.content;
        if (content) {
            db = JSON.parse(content);
            if (!db.friends) db.friends = [];
            if (!db.shared_routes) db.shared_routes = {};
            console.log('БД успешно загружена из Gist');
        }
    } catch (e) {
        console.error('Ошибка загрузки из Gist:', e.message);
    }
}

async function syncToGist() {
    if (!GIST_TOKEN || !GIST_ID) return;
    try {
        const res = await fetch(`https://api.github.com/gists/${GIST_ID}`, {
            method: 'PATCH',
            headers: { 
                'Authorization': `token ${GIST_TOKEN}`,
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                files: {
                    'enduro_db.json': { content: JSON.stringify(db) }
                }
            })
        });
        if (!res.ok) console.error('Ошибка сохранения в Gist', await res.text());
    } catch (e) {
        console.error('Network error saving to Gist:', e);
    }
}

// Загружаем локально или из Gist
if (fs.existsSync(DB_FILE) && !GIST_ID) {
    try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {}
} else if (GIST_ID) {
    syncFromGist();
}

if (!db.friends) db.friends = [];
if (!db.shared_routes) db.shared_routes = {};

function saveDb() {
    fs.writeFileSync(DB_FILE, JSON.stringify(db), 'utf8');
    syncToGist(); // Асинхронно пушим в облако
}

// Middleware проверки токена
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// ================= AUTH =================
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Нужен логин и пароль' });

    if (db.users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'Логин уже занят' });
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        
        const newUser = { id: Date.now(), username, password: hash };
        db.users.push(newUser);
        saveDb();
        
        const token = jwt.sign({ id: newUser.id, username }, JWT_SECRET);
        res.json({ token, username });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = db.users.find(u => u.username === username);
    
    if (!user) return res.status(400).json({ error: 'Неверный логин или пароль' });

    bcrypt.compare(password, user.password, (err, result) => {
        if (result) {
            const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
            res.json({ token, username: user.username });
        } else {
            res.status(400).json({ error: 'Неверный логин или пароль' });
        }
    });
});

// ================= DATA =================
app.get('/data', authenticateToken, (req, res) => {
    const data = db.map_data[req.user.id];
    if (data) {
        res.json(JSON.parse(data));
    } else {
        res.json({});
    }
});

app.post('/data', authenticateToken, (req, res) => {
    db.map_data[req.user.id] = JSON.stringify(req.body);
    saveDb();
    res.json({ success: true });
});

// ================= FRIENDS =================
app.get('/friends', authenticateToken, (req, res) => {
    // Находим всех друзей пользователя
    const userFriends = db.friends.filter(f => f.user1 === req.user.id || f.user2 === req.user.id);
    const friendList = userFriends.map(f => {
        const friendId = f.user1 === req.user.id ? f.user2 : f.user1;
        const friendUser = db.users.find(u => u.id === friendId);
        return { id: friendId, username: friendUser?.username || 'Unknown' };
    });
    res.json(friendList);
});

app.post('/friends/add', authenticateToken, (req, res) => {
    const { friendUsername } = req.body;
    if (friendUsername === req.user.username) return res.status(400).json({ error: 'Нельзя добавить себя' });
    
    const friendUser = db.users.find(u => u.username === friendUsername);
    if (!friendUser) return res.status(404).json({ error: 'Пользователь не найден' });

    const exists = db.friends.find(f => 
        (f.user1 === req.user.id && f.user2 === friendUser.id) || 
        (f.user1 === friendUser.id && f.user2 === req.user.id)
    );

    if (exists) return res.status(400).json({ error: 'Уже в друзьях' });

    db.friends.push({ user1: req.user.id, user2: friendUser.id });
    saveDb();
    res.json({ success: true, friend: { id: friendUser.id, username: friendUser.username } });
});

app.get('/friends/:friendId/data', authenticateToken, (req, res) => {
    const friendId = parseInt(req.params.friendId);
    
    // Проверка дружбы
    const isFriend = db.friends.find(f => 
        (f.user1 === req.user.id && f.user2 === friendId) || 
        (f.user1 === friendId && f.user2 === req.user.id)
    );
    if (!isFriend) return res.status(403).json({ error: 'Это не ваш друг' });

    const data = db.map_data[friendId];
    if (data) res.json(JSON.parse(data));
    else res.json({});
});

// ================= ROUTE SHARING =================
app.post('/shared', authenticateToken, (req, res) => {
    const { route } = req.body; // Один объект маршрута
    if (!route) return res.status(400).json({ error: 'Нет маршрута' });

    // Генерируем рандомный ID 6 символов
    const sharedId = Math.random().toString(36).substring(2, 8);
    
    db.shared_routes[sharedId] = {
        owner: req.user.username,
        route: route,
        createdAt: new Date().toISOString()
    };
    saveDb();
    
    res.json({ sharedId });
});

app.get('/shared/:id', (req, res) => { // Без авторизации!
    const shared = db.shared_routes[req.params.id];
    if (!shared) return res.status(404).json({ error: 'Маршрут не найден или удален' });
    res.json(shared);
});

app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT} (JSON DB)`);
});
