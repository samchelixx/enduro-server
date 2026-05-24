const express = require('express');
const cors = require('cors');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'enduro-secret-key-123';
const DB_FILE = './enduro_db.json';

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Инициализация базы данных (JSON файл вместо SQLite)
let db = { users: [], map_data: {} };
if (fs.existsSync(DB_FILE)) {
    try {
        db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch (e) {
        console.error('Ошибка чтения БД', e);
    }
}

function saveDb() {
    fs.writeFileSync(DB_FILE, JSON.stringify(db), 'utf8');
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

// Регистрация
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

// Логин
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

// Получение данных карты
app.get('/data', authenticateToken, (req, res) => {
    const data = db.map_data[req.user.id];
    if (data) {
        res.json(JSON.parse(data));
    } else {
        res.json({});
    }
});

// Сохранение данных карты
app.post('/data', authenticateToken, (req, res) => {
    db.map_data[req.user.id] = JSON.stringify(req.body);
    saveDb();
    res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT} (JSON DB)`);
});
