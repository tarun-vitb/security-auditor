// Express router with file-level authentication middleware
// This file should NOT trigger missing auth warnings
const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');

// All routes below are protected by this middleware
router.use(authenticate);

router.get('/users', (req, res) => {
    res.json({ users: [] });
});

router.post('/users', (req, res) => {
    res.json({ created: true });
});

router.put('/users/:id', (req, res) => {
    res.json({ updated: true });
});

router.delete('/users/:id', (req, res) => {
    res.json({ deleted: true });
});

module.exports = router;
