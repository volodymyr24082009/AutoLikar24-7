const express = require("express");
const bodyParser = require("body-parser");
const { Pool } = require("pg");
const path = require("path");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
dotenv.config();

const app = express();
const port = 3000;

// Підключення до бази даних
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false },
});

// Створення таблиці, якщо вона не існує
const createTable = async () => {
  const query = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL
    );
  `;

  try {
    await pool.query(query);
    console.log('Таблиця користувачів успішно створена або вже існує.');
  } catch (err) {
    console.error('Помилка при створенні таблиці:', err);
  }
};

// Викликаємо створення таблиці перед запуском сервера
createTable();

// Мідлвари
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// GET маршрут для головної сторінки (сторінка реєстрації / авторизації)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "auth.html"));
});

let isProcessing = false;

// ✅ Реєстрація користувача

app.post('/register', async (req, res) => {
    if (isProcessing) {
      return res.status(400).json({ message: 'Запит уже обробляється!' });
    }
    isProcessing = true;
  
    const { username, password } = req.body;
  
    // Перевірка, чи всі поля заповнені
    if (!username || !password) {
      isProcessing = false;
      return res.status(400).json({ message: 'Усі поля мають бути заповнені!' });
    }
  
    try {
      // Перевірка, чи користувач з таким ім'ям вже існує
      const existingUser = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      if (existingUser.rows.length > 0) {
        isProcessing = false;
        return res.status(400).json({ message: 'Користувач з таким ім’ям вже існує!' });
      }
  
      // Хешування пароля
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
  
      // Виведення в консоль після хешування пароля
      console.log('Пароль успішно захешовано:', hashedPassword);
  
      // Додавання нового користувача до бази даних
      const result = await pool.query(
        'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *',
        [username, hashedPassword]
      );
  
      // Виведення в консоль після успішної реєстрації користувача
      console.log(`Користувач ${username} успішно зареєстрований та перенесений в таблицю 'users'.`);
  
      res.status(201).json({ message: 'Ви успішно зареєстровані!', user: result.rows[0] });
    } catch (err) {
      console.error('Помилка при реєстрації:', err);
      res.status(500).json({ message: 'Помилка сервера', error: err.message });
    } finally {
      isProcessing = false;
    }
  });
  
// ✅ Логін користувача
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Усі поля мають бути заповнені!' });
  }

  try {
    // Шукаємо користувача за ім'ям
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Невірне ім’я користувача або пароль!' });
    }

    const user = result.rows[0];

    // Перевірка пароля
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Невірне ім’я користувача або пароль!' });
    }

    res.status(200).json({ message: 'Вхід успішний!', user });
  } catch (err) {
    console.error('Помилка при вході:', err);
    res.status(500).json({ message: 'Помилка сервера', error: err.message });
  }
});

// Запуск сервера
app.listen(port, () => {
  console.log(`Сервер запущено на http://localhost:${port}`);
});
