// JavaScript sample with multiple vulnerabilities
const express = require('express');
const mysql = require('mysql');
const app = express();

// Hardcoded credentials
const API_KEY = "api_key_1234567890abcdef";
const DB_PASSWORD = "root_password_123";

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: DB_PASSWORD,
    database: 'myapp'
});

// SQL Injection via template literal
app.get('/user/:id', (req, res) => {
    const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
    connection.query(query, (err, results) => {
        res.json(results);
    });
});

// No authentication on sensitive route
app.post('/admin/create', (req, res) => {
    // Missing auth middleware
    res.json({ created: true });
});

app.delete('/api/users/:id', (req, res) => {
    // DELETE without authentication
    res.json({ deleted: req.params.id });
});
