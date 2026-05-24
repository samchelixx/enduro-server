const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'enduro-secret-key-123'; // В продакшене вынести в .env

app.use(cors());
app.use(express.json({ limit: '50mb' })); // Для сохранения больших карт

// Инициализация базы данных
const db = new sqlite3.Database('./enduro.db', (err) => {
    if (err) console.error('Ошибка БД:', err);
    else {
        console.log('Подключено к SQLite');
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS map_data (
            user_id INTEGER PRIMARY KEY,
            data TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);
    }
});

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

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Логин уже занят' });
                return res.status(500).json({ error: 'Ошибка БД' });
            }
            
            const token = jwt.sign({ id: this.lastID, username }, JWT_SECRET);
            res.json({ token, username });
        });
    });
});

// Логин
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка БД' });
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
});

// Получение данных карты
app.get('/data', authenticateToken, (req, res) => {
    db.get('SELECT data FROM map_data WHERE user_id = ?', [req.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: 'Ошибка БД' });
        if (row) {
            res.json(JSON.parse(row.data));
        } else {
            res.json({}); // Нет данных
        }
    });
});

// Сохранение данных карты
app.post('/data', authenticateToken, (req, res) => {
    const dataStr = JSON.stringify(req.body);
    
    db.run(`INSERT INTO map_data (user_id, data) VALUES (?, ?)
            ON CONFLICT(user_id) DO UPDATE SET data = excluded.data`,
    [req.user.id, dataStr], (err) => {
        if (err) return res.status(500).json({ error: 'Ошибка сохранения' });
        res.json({ success: true });
    });
});

app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
