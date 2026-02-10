// TypeScript sample with vulnerabilities
import express, { Request, Response } from 'express';
import { Pool } from 'pg';

const app = express();

// Hardcoded secret
const JWT_SECRET = "my_super_secret_jwt_key_12345678";
const token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

const pool = new Pool({
    connectionString: "postgres://user:secretpass123@localhost/db"
});

// SQL Injection
app.get('/query', async (req: Request, res: Response) => {
    const searchTerm = req.query.q;
    const result = await pool.query(`SELECT * FROM items WHERE name = '${searchTerm}'`);
    res.json(result.rows);
});

// Missing auth on admin endpoint
app.post('/admin/settings', (req: Request, res: Response) => {
    // No authentication check
    res.json({ updated: true });
});

app.put('/user/role', (req: Request, res: Response) => {
    // Privilege escalation without auth
    res.json({ role: 'admin' });
});
