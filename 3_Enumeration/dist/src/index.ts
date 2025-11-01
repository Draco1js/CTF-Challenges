import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv'
dotenv.config({ quiet: true })
dotenv.config({ path: '../', quiet: true })
dotenv.config({ path: '../../', quiet: true }) // If it's on another path

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const JWT_SECRET = '6Idu0hZ6miLmBktSfv8N5CfYPxBK0IPV'; // The vuln is using the same secret for both environments as well as enumerating IDs, and not protecting endpoints

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON bodies and cookies
app.use(express.json());
app.use(cookieParser());

// Disable ETag for API routes to prevent 304 responses with empty bodies
app.set('etag', false);

// Serve static files (e.g., HTML pages) from "public" directory
app.use(express.static(path.join(__dirname, '../public')));

// Route handlers for frontend pages
app.get('/', (req: Request, res: Response) => {
	res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.get('/dev-panel', (req: Request, res: Response) => {
	res.sendFile(path.join(__dirname, '../public/dev-panel.html'));
});

app.get('/dashboard', (req: Request, res: Response) => {
	res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

app.get('/admin-dashboard', (req: Request, res: Response) => {
	res.sendFile(path.join(__dirname, '../public/admin-dashboard.html'));
});

// Dummy user enumeration (for demo! In real apps, never do auth like this)
let mainAppUsers = [
	{ userId: 1, username: "jasper@domain.com", password: "fUxN4WgRp9qP2LpA", role: "user", enabled: true },
	{ userId: 2, username: "leila@domain.com", password: "Qm3Vsf5dB7zXw2cJ", role: "user", enabled: true },
	{ userId: 3, username: "mira@domain.com", password: "pP0mVrSy4Kh6nQEo", role: "user", enabled: true },
	{ userId: 4, username: "zane@domain.com", password: "uS2vFb4Hc81TrGoa", role: "user", enabled: false },
	{ userId: 5, username: "kieran@domain.com", password: "9KwzJ7DiA4nG3Bxc", role: "user", enabled: false },
	{ userId: 6, username: "talia@domain.com", password: "L5yoEp7Qw8GtZw3b", role: "user", enabled: true },
	{ userId: 7, username: "auren@domain.com", password: "fD8bCg2Rv6UpXe1o", role: "admin", enabled: false, flag: 'this account is disabled' }, // Since the new admin user will be id 7, they will get a hint that admin users have a 'flag' field on them
	{ userId: 8, username: "yanis@domain.com", password: "zP1Aw7h5RnETcK3U", role: "user", enabled: false },
	{ userId: 9, username: "rocco@domain.com", password: "Q2TkW6oP19sUFx8V", role: "admin", enabled: false },
	{ userId: 10, username: "zuri@domain.com", password: "CgA6ShPd8vGL0iQw", role: "user", enabled: true },
	{ userId: 11, username: "brina@domain.com", password: "Ut3dqO7yVg2zp5Ac", role: "user", enabled: true },
	{ userId: 12, username: "vaughn@domain.com", password: "7Xk2nQLtBw9Tf3rS", role: "user", enabled: true },
	{ userId: 13, username: "korra@domain.com", password: "p5XmqKlS39vEr8Ct", role: "admin", enabled: false, flag: 'this account is disabled' },
	{ userId: 14, username: "amir@domain.com", password: "W0csDvL6Yj8u4KwV", role: "user", enabled: false },
	{ userId: 15, username: "activeadmin@domain.com", password: "F7gTqPz9xN6vHb4U", role: "admin", enabled: true, flag: process.env.FLAG },
	{ userId: 16, username: "elara@domain.com", password: "H3rWqP9xT8dLk5Bs", role: "user", enabled: true },
	{ userId: 17, username: "cyrus@domain.com", password: "nD7pLm3Rz2XwQc9J", role: "user", enabled: true },
	{ userId: 18, username: "ines@domain.com", password: "L6qNf2PrBd4Cj1Wx", role: "user", enabled: true },
	{ userId: 19, username: "ronan@domain.com", password: "Vk4yHs9wJ7lUx3Ba", role: "user", enabled: true },
	{ userId: 20, username: "neve@domain.com", password: "Qp2jYz0Fs8VwMu6L", role: "user", enabled: false }
];

let adminAppUsers = [
	{ userId: 1, username: "alice.admin@gmail.com", password: "p@ssw0rdA1" },
	{ userId: 2, username: "bob.admin@yahoo.com", password: "s3cur3B0b!" },
	{ userId: 3, username: "carol.admin@hotmail.com", password: "C@r0lPwd42" },
	{ userId: 4, username: "dave.admin@gmail.com", password: "D4v3secure#" },
	{ userId: 5, username: "eve.admin@yahoo.com", password: "Ev3!Admin21" },
	{ userId: 6, username: "frank.admin@hotmail.com", password: "FrAnK_pwD9" }
];

// Helper function to validate @domain.com email
function validateDomainEmail(email: string): boolean {
	if (typeof email !== 'string') return false;
	// must end with exactly @domain.com (case sensitive)
	const regex = /^[a-zA-Z0-9._+-]+@domain\.com$/;
	const match = email.match(regex);
	const parts = email.split('@');
	if (parts.length !== 2 || !match) return false;
	return parts[1] === 'domain.com';
}

// --- Admin Registration Endpoint ---
app.post('/api/admin/register', (req: Request, res: Response) => {
	const { username, password } = req.body;

	if (!username || !password) {
		return res.status(400).json({ error: "Username and password are required" });
	}

	if (typeof username !== 'string' || typeof password !== 'string') {
		return res.status(400).json({ error: "Username and password must be strings" });
	}

	// Check if user already exists
	if (adminAppUsers.find(u => u.username === username)) {
		return res.status(409).json({ error: "User already exists" });
	}

	// Generate new userId by enumerating
	const newUserId = Math.max(...adminAppUsers.map(u => u.userId)) + 1;
	adminAppUsers.push({ userId: newUserId, username, password });
	const token = jwt.sign({ userId: newUserId }, JWT_SECRET);

	res.cookie('dev-token', token, {
		httpOnly: true,
		secure: false,
		sameSite: 'lax',
	});

	return res.json({ message: "Admin user created successfully" });
});

// --- Admin Login Endpoint ---
app.post('/api/admin/login', (req: Request, res: Response) => {
	const { username, password } = req.body;

	if (!username || !password) {
		return res.status(400).json({ error: "Username and password are required" });
	}

	if (typeof username !== 'string' || typeof password !== 'string') {
		return res.status(400).json({ error: "Username and password must be strings" });
	}

	const trimmedUsername = username.trim();
	const trimmedPassword = password.trim();

	const user = adminAppUsers.find(u => u.username === trimmedUsername && u.password === trimmedPassword);
	if (!user) {
		return res.status(401).json({ error: "Invalid credentials" });
	}

	// Only encode userId, also a bad practice lol
	const token = jwt.sign({ userId: user.userId }, JWT_SECRET);

	res.cookie('dev-token', token, {
		httpOnly: true,
		secure: false,
		sameSite: 'lax',
	});

	return res.json({ message: "Login successful" });
});

// --- Main App User Registration Endpoint ---
app.post('/api/app/register', (req: Request, res: Response) => {
	const { username, password } = req.body;

	if (!username || !password) {
		return res.status(400).json({ error: "Username and password are required" });
	}

	if (typeof username !== 'string' || typeof password !== 'string') {
		return res.status(400).json({ error: "Username and password must be strings" });
	}

	// Block all emails since they realistically can't have an @domain.com email
	return res.status(404).json({ error: "Email address not found" });
});

// --- Main App User Login Endpoint ---
app.post('/api/app/login', (req: Request, res: Response) => {
	const { username, password } = req.body;
	const user = mainAppUsers.find(u => u.username === username && u.password === password);

	if (!user) {
		return res.status(401).json({ error: "Invalid credentials" });
	}
	const token = jwt.sign({ userId: user.userId }, JWT_SECRET);

	res.cookie('token-for-prod', token, {
		httpOnly: true,
		secure: false,
		sameSite: 'lax',
	});

	return res.json({ message: "Login successful" });
});

// Extend Request interface to include user property
interface AuthRequest extends Request {
	user?: any;
}

// --- Auth Middleware ---
function authenticateJWT(req: AuthRequest, res: Response, next: NextFunction) {

	// Disable caching to prevent 304 responses with empty bodies
	res.set({
		'Cache-Control': 'no-store, no-cache, must-revalidate, private',
		'Pragma': 'no-cache',
		'Expires': '0',
		'ETag': false
	});

	// Check for either user or dev cookie
	let token = req.cookies['token-for-prod'];
	if (!token) {
		token = req.cookies['dev-token'];
	}

	if (!token) {
		return res.status(401).json({ error: "Authentication required" });
	}

	try {
		req.user = jwt.verify(token, JWT_SECRET);
		next();
	} catch (err) {
		return res.status(401).json({ error: "Invalid or expired token" });
	}
}

// --- /api/me endpoint (only for appUsers) ---
app.get('/api/me', authenticateJWT, (req: AuthRequest, res: Response) => {
	const { userId } = req.user;
	const user = mainAppUsers.find(u => u.userId === userId);

	if (!user) {
		return res.status(404).json({ error: "User not found" });
	}

	const response: any = {
		userId: user.userId,
		username: user.username,
		role: user.role,
		enabled: user.enabled
	};


	// Include flag if the user has one
	if ('flag' in user) {
		response.flag = (user as any).flag;
	}

	res.json(response);
});

// --- /api/admin/me endpoint (only for adminUsers) ---
app.get('/api/admin/me', authenticateJWT, (req: AuthRequest, res: Response) => {
	const { userId } = req.user;
	const user = adminAppUsers.find(u => u.userId === userId);

	if (!user) {
		return res.status(403).json({ error: "Forbidden" });
	}

	res.json({
		userId: user.userId,
		username: user.username,
		authenticated: true
	});
});

// --- POST to get all app users (vuln here, only checks if you're logged in, not if you're an admin) ---
app.post('/api/users', authenticateJWT, (req: AuthRequest, res: Response) => {
	const userId = req.user.userId;
	const user = mainAppUsers.find(u => u.userId === userId && u.role === 'admin');
	if (!user) return res.status(403).json({ error: "Unauthorized, need an admin account to check this." });
	// Only show emails, userIds, roles, and enabled status (no flag property)
	const users = mainAppUsers.map(u => ({
		userId: u.userId,
		username: u.username,
		role: u.role,
		enabled: u.enabled
	}));
	res.json({ users });
});

// --- /api endpoint - Lists all available endpoints ---
app.get('/api', (req: Request, res: Response) => {
	const endpoints = {
		"authentication": {
			"POST /api/app/login": "Login with app credentials (@domain.com email required)",
			"POST /api/app/register": "Register new app user (@domain.com email required)",
			"POST /api/admin/login": "Admin login",
			"POST /api/admin/register": "Admin registration",
			"POST /api/auth/refresh": "Refresh authentication token",
			"POST /api/auth/logout": "Logout and invalidate token"
		},
		"user_management": {
			"GET /api/me": "Get current user profile (requires authentication)",
			"POST /api/users": "Get all users (requires authentication)",
			"GET /api/user/:id": "Get user by ID (requires authentication)",
			"PUT /api/user/:id": "Update user (requires admin authentication)",
			"DELETE /api/user/:id": "Delete user (requires admin authentication)",
			"GET /api/users/search": "Search users by query (requires authentication)",
			"GET /api/users/:id/posts": "Get user posts (requires authentication)"
		},
		"admin_functions": {
			"GET /api/admin/users": "List all admin users (requires admin authentication)",
			"GET /api/admin/stats": "Get system statistics (requires admin authentication)",
			"POST /api/admin/settings": "Update system settings (requires admin authentication)",
			"GET /api/admin/logs": "View system logs (requires admin authentication)",
			"POST /api/admin/ban": "Ban a user (requires admin authentication)",
			"GET /api/admin/reports": "View user reports (requires admin authentication)"
		},
		"data_endpoints": {
			"GET /api/data/export": "Export user data (requires authentication)",
			"POST /api/data/import": "Import user data (requires admin authentication)",
			"GET /api/data/backup": "Get database backup (requires admin authentication)"
		},
		"misc": {
			"GET /api/health": "Health check endpoint",
			"GET /api/version": "Get API version",
			"GET /api/docs": "API documentation",
			"GET /api/config": "Get API configuration",
			"GET /api/status": "Get API status"
		}
	};
	res.json({
		message: "Welcome to the API",
		endpoints,
		version: "1.0.0"
	});
});

// --- Dummy endpoints to confuse attackers ---
app.get('/api/user/:id', authenticateJWT, (req: AuthRequest, res: Response) => {
	const idParam = req.params.id;
	if (!idParam) {
		return res.status(400).json({ error: "Invalid user ID" });
	}
	const userId = parseInt(idParam);
	if (isNaN(userId)) {
		return res.status(400).json({ error: "Invalid user ID" });
	}
	const user = mainAppUsers.find(u => u.userId === userId);
	if (!user) {
		return res.status(404).json({ error: "User not found" });
	}
	// Intentionally don't show flag property here
	res.json({ userId: user.userId, username: user.username, role: user.role, enabled: user.enabled });
});

app.put('/api/user/:id', authenticateJWT, (req: AuthRequest, res: Response) => {
	res.status(403).json({ error: "Insufficient permissions. Admin role required." });
});

app.delete('/api/user/:id', authenticateJWT, (req: AuthRequest, res: Response) => {
	res.status(403).json({ error: "Insufficient permissions. Admin role required." });
});

app.post('/api/auth/refresh', authenticateJWT, (req: AuthRequest, res: Response) => {
	res.status(501).json({ error: "Token refresh not implemented yet" });
});

app.post('/api/auth/logout', authenticateJWT, (req: AuthRequest, res: Response) => {
	// Clear both possible cookies
	res.clearCookie('token-for-prod', { path: '/' });
	res.clearCookie('dev-token', { path: '/' });
	res.json({ message: "Logged out successfully" });
});

app.get('/api/users/search', authenticateJWT, (req: AuthRequest, res: Response) => {
	const query = req.query.q as string;
	if (!query) {
		return res.status(400).json({ error: "Search query required" });
	}
	// Only return basic info, no flag
	const results = mainAppUsers
		.filter(u => u.username.toLowerCase().includes(query.toLowerCase()))
		.map(u => ({ userId: u.userId, username: u.username, role: u.role }));
	res.json({ results, count: results.length });
});

app.get('/api/users/:id/posts', authenticateJWT, (req: AuthRequest, res: Response) => {
	res.status(404).json({ error: "Posts feature not implemented" });
});

app.get('/api/admin/users', authenticateJWT, (req: AuthRequest, res: Response) => {
	res.status(403).json({ error: "Admin access required. Your role does not have sufficient permissions." });
});

app.get('/api/admin/stats', authenticateJWT, (req: AuthRequest, res: Response) => {
	res.status(403).json({ error: "Admin access required. Your role does not have sufficient permissions." });
});

app.post('/api/admin/settings', authenticateJWT, (req: AuthRequest, res: Response) => {
	res.status(403).json({ error: "Admin access required. Your role does not have sufficient permissions." });
});

app.get('/api/admin/logs', authenticateJWT, (req: AuthRequest, res: Response) => {
	res.status(403).json({ error: "Admin access required" });
});

app.post('/api/admin/ban', authenticateJWT, (req: AuthRequest, res: Response) => {
	res.status(403).json({ error: "Admin access required" });
});

app.get('/api/admin/reports', authenticateJWT, (req: AuthRequest, res: Response) => {
	res.status(403).json({ error: "Admin access required" });
});

app.get('/api/data/export', authenticateJWT, (req: AuthRequest, res: Response) => {
	res.status(503).json({ error: "Data export service temporarily unavailable" });
});

app.post('/api/data/import', authenticateJWT, (req: AuthRequest, res: Response) => {
	res.status(403).json({ error: "Admin access required for data import" });
});

app.get('/api/data/backup', authenticateJWT, (req: AuthRequest, res: Response) => {
	res.status(403).json({ error: "Admin access required for backups" });
});

app.get('/api/health', (req: Request, res: Response) => {
	res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

app.get('/api/version', (req: Request, res: Response) => {
	res.json({ version: "1.0.0", build: "2024-01-15" });
});

app.get('/api/docs', (req: Request, res: Response) => {
	res.json({
		message: "API documentation is available at /api",
		note: "Use GET /api to see all available endpoints"
	});
});

app.get('/api/config', (req: Request, res: Response) => {
	res.json({
		message: "Configuration endpoint is disabled",
		reason: "Security policy"
	});
});

app.get('/api/status', (req: Request, res: Response) => {
	res.json({
		status: "operational",
		uptime: "99.9%",
		timestamp: new Date().toISOString()
	});
});

// Start the server
app.listen(PORT, () => {
	console.log(`Server is running on http://localhost:${PORT}`);
	console.log("Running with flag: ", process.env.FLAG)
});
