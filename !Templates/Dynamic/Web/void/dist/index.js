const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Retrieve the key based on kID, handling empty files or /dev/null with empty key logic
function getKeyFromKID(kID) {
    try {
        // Remove any backward directory traversal attempts (e.g., ../)
        const sanitizedKID = kID.replace(/(\.\.\/|\.\/)/g, '');
        
        // Construct the path within the 'keys' directory
        const keyPath = path.join(__dirname, 'keys', `${sanitizedKID}.key`);
        console.log(`Attempting to read key from: ${keyPath}`); // Debugging output

        // Check if the file exists, and read it if it does
        if (fs.existsSync(keyPath)) {
            const key = fs.readFileSync(keyPath, 'utf8').trim();

            // If key is empty, use a base64 null byte ("AA==") as the default key
            if (key === '') {
                console.warn(`Empty key file found at path ${keyPath}. Using base64 null byte as key.`);
                return Buffer.from([0]).toString('base64'); // "AA=="
            }
            return key; // Return the key if it's not empty
        } else {
            console.warn(`Key file not found at path ${keyPath}.`);
            return null;
        }
    } catch (err) {
        console.error(`Error loading key from kID ${kID}: ${err.message}`);
        return null; // Return null if key not found or error occurs
    }
}
// Generate JWT token after login
function generateToken(user) {
    const kID = '1'; // Default kID for signing
    const key = getKeyFromKID(kID);

    if (!key) {
        console.error('Signing key not found, unable to generate token.');
        throw new Error('Signing key not found.');
    }

    return jwt.sign(
        { username: user.username, role: user.role },
        Buffer.from(key, 'base64'), // Decode base64 key if encoded
        { algorithm: 'HS256', header: { kID } }
    );
}

// Temporary in-memory database for demonstration
const users = [
    { username: 'dumbAirStudent', password: 'password123', role: 'user' },
    { username: 'adminUser', password: 'adminpass', role: 'admin' }
];

// Login endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);

    if (!user) {
        return res.status(401).send('Invalid credentials.');
    }

    try {
        const token = generateToken(user);
        console.log(`Generated token for ${user.username}: ${token}`); // Log token for debugging
        res.cookie('token', token, { httpOnly: true });
        res.send('Login successful.');
    } catch (err) {
        res.status(500).send('Error generating token.');
    }
});

// Admin endpoint, accessible only if the token contains the 'admin' role
// Admin endpoint, accessible only if the token contains the 'admin' role
app.get('/admin', (req, res) => {
    const token = req.cookies?.token;
    console.log(`Received token in /admin: ${token}`); // Debugging output

    if (!token) {
        return res.status(401).send('Access denied. No token provided.');
    }

    // Decode token with the specified key from kID
    try {
        const decodedHeader = jwt.decode(token, { complete: true })?.header;
        const key = getKeyFromKID(decodedHeader.kID);

        if (!key) {
            console.warn(`Key not found or empty for kID ${decodedHeader.kID}, verification failed.`);
            return res.status(401).send('Invalid token.');
        }

        const decoded = jwt.verify(token, Buffer.from(key, 'base64')); // Decode base64 key for verification

        if (decoded.role === 'admin') {
            // Read and respond with the contents of flag.txt
            const flagPath = path.join(__dirname, 'flag.txt');
            if (fs.existsSync(flagPath)) {
                const flagContent = fs.readFileSync(flagPath, 'utf8');
                res.send(`Welcome to the admin panel! Here is your flag: ${flagContent}`);
            } else {
                res.status(500).send('Flag file not found.');
            }
        } else {
            res.status(403).send('Access denied. Admins only.');
        }
    } catch (err) {
        console.error(`Token verification failed: ${err.message}`);
        res.status(401).send('Invalid token.');
    }
});


// Serve login page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Start the server
app.listen(3000, () => {
    console.log('Challenge server running on http://localhost:3000');
});

