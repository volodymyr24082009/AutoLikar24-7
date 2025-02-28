const express = require("express");
const bodyParser = require("body-parser");
const { Pool } = require("pg");
const path = require("path");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const cors = require('cors');
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Підключення до бази даних
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false },
});

// Функція для створення таблиць
const createTables = async () => {
  const userTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL
    );
  `;

  const userProfileTableQuery = `
    CREATE TABLE IF NOT EXISTS user_profile (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      first_name VARCHAR(100),
      last_name VARCHAR(100),
      email VARCHAR(255),
      phone VARCHAR(15),
      address TEXT,
      date_of_birth DATE
    );
  `;

  const userServicesTableQuery = `
    CREATE TABLE IF NOT EXISTS user_services (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      service_name VARCHAR(255) NOT NULL
    );
  `;

  const addRoleMasterColumnQuery = `
    DO $$ 
    BEGIN 
      IF NOT EXISTS (
        SELECT FROM information_schema.columns 
        WHERE table_name = 'user_profile' AND column_name = 'role_master'
      ) THEN
        ALTER TABLE user_profile ADD COLUMN role_master BOOLEAN DEFAULT FALSE;
      END IF;
    END $$;
  `;

  try {
    await pool.query(userTableQuery);
    await pool.query(userProfileTableQuery);
    await pool.query(userServicesTableQuery);
    await pool.query(addRoleMasterColumnQuery);
    console.log('Таблиці створено або вже існують, колонку role_master додано (якщо її не було).');
  } catch (err) {
    console.error('Помилка при створенні таблиць:', err);
  }
};

createTables();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// Головна сторінка (реєстрація/авторизація)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "auth.html"));
});

// Допоміжна функція для виконання запитів до бази даних
const query = (text, params) => pool.query(text, params);

// Middleware для JWT аутентифікації
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

let isProcessing = false;

// Реєстрація користувача
app.post('/register', async (req, res) => {
  if (isProcessing) {
    return res.status(400).json({ message: 'Запит вже обробляється!' });
  }
  isProcessing = true;

  const { username, password } = req.body;

  if (!username || !password) {
    isProcessing = false;
    return res.status(400).json({ message: 'Усі поля повинні бути заповнені!' });
  }

  try {
    const existingUser = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) {
      isProcessing = false;
      return res.status(400).json({ message: 'Користувач з таким іменем вже існує!' });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id', 
      [username, hashedPassword]
    );
    
    await pool.query(
      'INSERT INTO user_profile (user_id) VALUES ($1)',
      [newUser.rows[0].id]
    );

    console.log(`Користувач ${username} успішно зареєстрований.`);

    res.status(200).json({ 
      success: true, 
      message: 'Реєстрація успішна', 
      userId: newUser.rows[0].id,
      redirect: '/index.html'
    });
  } catch (err) {
    console.error('Помилка при реєстрації:', err);
    res.status(500).json({ message: 'Помилка сервера', error: err.message });
  } finally {
    isProcessing = false;
  }
});

// Логін користувача
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Усі поля повинні бути заповнені!' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Невірне ім\'я користувача або пароль!' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Невірне ім\'я користувача або пароль!' });
    }

    console.log(`${username} успішно увійшов в систему!`);

    res.status(200).json({ 
      success: true, 
      message: 'Вхід успішний', 
      userId: user.id,
      redirect: '/index.html'
    });
  } catch (err) {
    console.error('Помилка при вході:', err);
    res.status(500).json({ message: 'Помилка сервера', error: err.message });
  }
});

// Отримання профілю користувача
app.get('/profile/:userId', async (req, res) => {
  const userId = req.params.userId;
  
  try {
    const profileResult = await pool.query(
      'SELECT * FROM user_profile WHERE user_id = $1',
      [userId]
    );
    
    if (profileResult.rows.length === 0) {
      return res.status(404).json({ message: 'Профіль не знайдено' });
    }
    
    res.status(200).json({ profile: profileResult.rows[0] });
  } catch (err) {
    console.error('Помилка при отриманні профілю:', err);
    res.status(500).json({ message: 'Помилка сервера', error: err.message });
  }
});

// Оновлення профілю користувача
app.put('/profile/:userId', async (req, res) => {
  const userId = req.params.userId;
  const { first_name, last_name, email, phone, address, date_of_birth, role_master } = req.body;
  
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Користувача не знайдено' });
    }
    
    await pool.query(
      `UPDATE user_profile 
       SET first_name = $1, last_name = $2, email = $3, phone = $4, 
           address = $5, date_of_birth = $6, role_master = $7
       WHERE user_id = $8`,
      [first_name, last_name, email, phone, address, date_of_birth, role_master, userId]
    );
    
    console.log(`Профіль користувача з ID ${userId} успішно оновлено.`);
    res.status(200).json({ success: true, message: 'Профіль успішно оновлено' });
  } catch (err) {
    console.error('Помилка при оновленні профілю:', err);
    res.status(500).json({ message: 'Помилка сервера', error: err.message });
  }
});

// Додавання послуги для користувача
app.post('/services/:userId', async (req, res) => {
  const userId = req.params.userId;
  const { service_name } = req.body;
  
  if (!service_name) {
    return res.status(400).json({ message: 'Назва послуги обов\'язкова' });
  }
  
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Користувача не знайдено' });
    }
    
    await pool.query(
      'INSERT INTO user_services (user_id, service_name) VALUES ($1, $2)',
      [userId, service_name]
    );
    
    console.log(`Послугу "${service_name}" додано для користувача з ID ${userId}.`);
    res.status(201).json({ success: true, message: 'Послугу успішно додано' });
  } catch (err) {
    console.error('Помилка при додаванні послуги:', err);
    res.status(500).json({ message: 'Помилка сервера', error: err.message });
  }
});

// Отримання послуг користувача
app.get('/services/:userId', async (req, res) => {
  const userId = req.params.userId;
  
  try {
    const servicesResult = await pool.query(
      'SELECT * FROM user_services WHERE user_id = $1',
      [userId]
    );
    
    res.status(200).json({ services: servicesResult.rows });
  } catch (err) {
    console.error('Помилка при отриманні послуг:', err);
    res.status(500).json({ message: 'Помилка сервера', error: err.message });
  }
});

// Видалення послуги
app.delete('/services/:serviceId', async (req, res) => {
  const serviceId = req.params.serviceId;
  
  try {
    const result = await pool.query(
      'DELETE FROM user_services WHERE id = $1 RETURNING *',
      [serviceId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Послугу не знайдено' });
    }
    
    console.log(`Послугу з ID ${serviceId} успішно видалено.`);
    res.status(200).json({ success: true, message: 'Послугу успішно видалено' });
  } catch (err) {
    console.error('Помилка при видаленні послуги:', err);
    res.status(500).json({ message: 'Помилка сервера', error: err.message });
  }
});

// Отримання списку всіх користувачів та майстрів
app.get('/admin/users', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.username, up.role_master, up.first_name, up.last_name, up.email
      FROM users u
      LEFT JOIN user_profile up ON u.id = up.user_id
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Помилка при отриманні списку користувачів:', err);
    res.status(500).json({ message: 'Помилка сервера', error: err.message });
  }
});

// Видалення користувача
app.delete('/admin/users/:userId', async (req, res) => {
  const userId = req.params.userId;
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    res.json({ message: 'Користувача успішно видалено' });
  } catch (err) {
    console.error('Помилка при видаленні користувача:', err);
    res.status(500).json({ message: 'Помилка сервера', error: err.message });
  }
});

// Запуск сервера
app.listen(port, () => {
  console.log(`Сервер запущено на http://localhost:${port}`);
});