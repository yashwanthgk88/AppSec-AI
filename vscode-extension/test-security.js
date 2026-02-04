// Test file for security scanner

// Hardcoded credentials (should be detected)
const password = "super_secret_123";
const apiKey = "sk-1234567890abcdef1234567890abcdef";

// SQL Injection vulnerability
function getUserData(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return db.execute(query);
}

// Command Injection vulnerability
function runCommand(userInput) {
    const { exec } = require('child_process');
    exec("ls -la " + userInput);
}

// XSS vulnerability
function displayMessage(message) {
    document.getElementById('output').innerHTML = message;
}

// Eval usage (code injection)
function processData(data) {
    return eval(data);
}

// Weak cryptography
const crypto = require('crypto');
function hashPassword(pwd) {
    return crypto.createHash('md5').update(pwd).digest('hex');
}

// Insecure random
function generateToken() {
    return Math.random().toString(36);
}

// SSRF potential
async function fetchData(url) {
    const userUrl = req.query.url;
    const response = await fetch(userUrl);
    return response.json();
}
