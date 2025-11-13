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

// ANSI color codes for terminal output
const colors = {
	reset: '\x1b[0m',
	bright: '\x1b[1m',
	dim: '\x1b[2m',
	red: '\x1b[31m',
	green: '\x1b[32m',
	yellow: '\x1b[33m',
	blue: '\x1b[34m',
	magenta: '\x1b[35m',
	cyan: '\x1b[36m',
	white: '\x1b[37m',
	gray: '\x1b[90m',
};

// Extract browser name from user agent
function parseUserAgent(ua: string): string {
	if (!ua || ua === 'unknown') return 'unknown';
	
	if (ua.includes('Chrome') && !ua.includes('Edg')) return 'Chrome';
	if (ua.includes('Firefox')) return 'Firefox';
	if (ua.includes('Safari') && !ua.includes('Chrome')) return 'Safari';
	if (ua.includes('Edg')) return 'Edge';
	if (ua.includes('Opera')) return 'Opera';
	if (ua.includes('curl')) return 'curl';
	if (ua.includes('Postman')) return 'Postman';
	if (ua.includes('wget')) return 'wget';
	
	return 'Other';
}

// Get color for action type
function getActionColor(action: string): string {
	if (action.includes('SUCCESS') || action.includes('_SUCCESS')) return colors.green;
	if (action.includes('FAILED') || action.includes('_FAILED')) return colors.red;
	if (action.includes('ATTEMPT') || action.includes('REQUEST')) return colors.yellow;
	if (action.includes('LOGIN') || action.includes('REGISTER')) return colors.cyan;
	if (action.includes('AUTH')) return colors.magenta;
	return colors.blue;
}

// Comprehensive logging utility
function logAction(action: string, details: Record<string, any>, req: Request, res?: Response) {
	const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
	const ip = req.ip || req.socket.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
	const userAgent = parseUserAgent(req.headers['user-agent'] || 'unknown');
	const method = req.method;
	const path = req.path || req.url;
	const cookies = req.cookies || {};
	const hasToken = !!(cookies['token-for-prod'] || cookies['dev-token']);
	const tokenType = cookies['token-for-prod'] ? 'prod' : (cookies['dev-token'] ? 'dev' : 'none');
	
	// Sanitize sensitive data from request body
	let sanitizedBody: any = undefined;
	if (req.body && Object.keys(req.body).length > 0) {
		sanitizedBody = { ...req.body };
		if (sanitizedBody.password) sanitizedBody.password = '[REDACTED]';
	}
	
	// Extract key details (remove unnecessary fields)
	const keyDetails: Record<string, any> = {};
	
	// Only include important CTF-relevant fields
	const importantFields = [
		'userId', 'requestedUserId', 'targetUserId', 'requestedByUserId',
		'username', 'targetUsername', 'requestedByUsername',
		'role', 'targetRole', 'requestingUserRole', 'userRole',
		'enabled', 'targetEnabled', 'userEnabled',
		'searchQuery', 'query', 'targetUserId', 'emailDomain',
		'userCount', 'resultCount', 'usersReturned',
		'flagIncluded', 'hasFlag',
		'reason', 'description',
		'isAdmin', 'usernameExists', 'userExists',
		'newUserId', 'existingUserId'
	];
	
	for (const [key, value] of Object.entries(details)) {
		if (importantFields.includes(key) || key.startsWith('reason') || key.startsWith('description')) {
			keyDetails[key] = value;
		}
	}
	
	// Build compact log entry
	const statusCode = res?.statusCode;
	const statusColor = statusCode && statusCode >= 400 ? colors.red : (statusCode && statusCode >= 300 ? colors.yellow : colors.green);
	const actionColor = getActionColor(action);
	
	// Format: timestamp | action | method path | ip | browser | token | status | details
	const parts = [
		`${colors.gray}${timestamp}${colors.reset}`,
		`${actionColor}${action.padEnd(25)}${colors.reset}`,
		`${colors.cyan}${method.padEnd(4)}${colors.reset} ${colors.dim}${path}${colors.reset}`,
		`${colors.blue}IP:${ip}${colors.reset}`,
		`${colors.gray}${userAgent}${colors.reset}`,
		hasToken ? `${colors.magenta}TOKEN:${tokenType}${colors.reset}` : `${colors.dim}no-auth${colors.reset}`,
		statusCode ? `${statusColor}${statusCode}${colors.reset}` : ''
	].filter(Boolean);
	
	console.log(parts.join(' | '));
	
	// Print key details if any, indented
	if (Object.keys(keyDetails).length > 0) {
		const detailStr = Object.entries(keyDetails)
			.map(([k, v]) => `${colors.dim}${k}${colors.reset}=${colors.white}${JSON.stringify(v)}${colors.reset}`)
			.join(' ');
		console.log(`  ${colors.dim}└─${colors.reset} ${detailStr}`);
	}
	
	// Separator line for readability
	console.log(`${colors.dim}${'─'.repeat(100)}${colors.reset}`);
}

// Middleware to parse JSON bodies and cookies
app.use(express.json());
app.use(cookieParser());

// Trust proxy to get real IP addresses
app.set('trust proxy', true);

// Global request logging middleware - logs ALL incoming requests
app.use((req: Request, res: Response, next: NextFunction) => {
	// Skip logging for static file requests (CSS, JS, images, etc.)
	if (req.path.match(/\.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot)$/)) {
		return next();
	}
	
	// Only log non-API page visits here (API endpoints have their own detailed logging)
	if (!req.path.startsWith('/api')) {
		logAction('PAGE_REQUEST', {
			description: 'Page access'
		}, req);
	}
	
	next();
});

// Disable ETag for API routes to prevent 304 responses with empty bodies
app.set('etag', false);

// Serve static files (e.g., HTML pages) from "public" directory
app.use(express.static(path.join(__dirname, '../public')));

// Route handlers for frontend pages
app.get('/', (req: Request, res: Response) => {
	logAction('PAGE_VISIT', { page: 'index.html', description: 'User visited main login/register page' }, req, res);
	res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.get('/dev-panel', (req: Request, res: Response) => {
	logAction('PAGE_VISIT', { page: 'dev-panel.html', description: 'User visited developer panel login page' }, req, res);
	res.sendFile(path.join(__dirname, '../public/dev-panel.html'));
});

app.get('/dashboard', (req: Request, res: Response) => {
	const cookies = req.cookies || {};
	const hasToken = !!(cookies['token-for-prod'] || cookies['dev-token']);
	logAction('PAGE_VISIT', { 
		page: 'dashboard.html', 
		description: 'User attempted to access dashboard',
		hasAuthenticationToken: hasToken,
		tokenPresent: hasToken
	}, req, res);
	res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

app.get('/admin-dashboard', (req: Request, res: Response) => {
	const cookies = req.cookies || {};
	const hasToken = !!(cookies['token-for-prod'] || cookies['dev-token']);
	logAction('PAGE_VISIT', { 
		page: 'admin-dashboard.html', 
		description: 'User attempted to access admin dashboard',
		hasAuthenticationToken: hasToken,
		tokenPresent: hasToken
	}, req, res);
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

	logAction('ADMIN_REGISTER_ATTEMPT', {
		description: 'User attempted to register admin account',
		username: username,
		usernameLength: username?.length,
		passwordLength: password?.length,
		hasUsername: !!username,
		hasPassword: !!password
	}, req);

	if (!username || !password) {
		logAction('ADMIN_REGISTER_FAILED', {
			reason: 'Missing username or password',
			hasUsername: !!username,
			hasPassword: !!password
		}, req, res);
		return res.status(400).json({ error: "Username and password are required" });
	}

	if (typeof username !== 'string' || typeof password !== 'string') {
		logAction('ADMIN_REGISTER_FAILED', {
			reason: 'Invalid data types',
			usernameType: typeof username,
			passwordType: typeof password
		}, req, res);
		return res.status(400).json({ error: "Username and password must be strings" });
	}

	// Check if user already exists
	const existingUser = adminAppUsers.find(u => u.username === username);
	if (existingUser) {
		logAction('ADMIN_REGISTER_FAILED', {
			reason: 'User already exists',
			username: username,
			existingUserId: existingUser.userId
		}, req, res);
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

	logAction('ADMIN_REGISTER_SUCCESS', {
		description: 'Admin user successfully registered',
		username: username,
		newUserId: newUserId,
		tokenGenerated: true,
		cookieSet: 'dev-token'
	}, req, res);

	return res.json({ message: "Admin user created successfully" });
});

// --- Admin Login Endpoint ---
app.post('/api/admin/login', (req: Request, res: Response) => {
	const { username, password } = req.body;

	logAction('ADMIN_LOGIN_ATTEMPT', {
		description: 'User attempted admin login',
		username: username,
		usernameLength: username?.length,
		passwordLength: password?.length,
		hasUsername: !!username,
		hasPassword: !!password
	}, req);

	if (!username || !password) {
		logAction('ADMIN_LOGIN_FAILED', {
			reason: 'Missing username or password',
			hasUsername: !!username,
			hasPassword: !!password
		}, req, res);
		return res.status(400).json({ error: "Username and password are required" });
	}

	if (typeof username !== 'string' || typeof password !== 'string') {
		logAction('ADMIN_LOGIN_FAILED', {
			reason: 'Invalid data types',
			usernameType: typeof username,
			passwordType: typeof password
		}, req, res);
		return res.status(400).json({ error: "Username and password must be strings" });
	}

	const trimmedUsername = username.trim();
	const trimmedPassword = password.trim();

	const user = adminAppUsers.find(u => u.username === trimmedUsername && u.password === trimmedPassword);
	if (!user) {
		logAction('ADMIN_LOGIN_FAILED', {
			reason: 'Invalid credentials',
			username: trimmedUsername,
			usernameExists: adminAppUsers.some(u => u.username === trimmedUsername),
			attemptedPasswordMatch: false
		}, req, res);
		return res.status(401).json({ error: "Invalid credentials" });
	}

	// Only encode userId, also a bad practice lol
	const token = jwt.sign({ userId: user.userId }, JWT_SECRET);

	res.cookie('dev-token', token, {
		httpOnly: true,
		secure: false,
		sameSite: 'lax',
	});

	logAction('ADMIN_LOGIN_SUCCESS', {
		description: 'Admin login successful',
		username: trimmedUsername,
		userId: user.userId,
		tokenGenerated: true,
		cookieSet: 'dev-token'
	}, req, res);

	return res.json({ message: "Login successful" });
});

// --- Main App User Registration Endpoint ---
app.post('/api/app/register', (req: Request, res: Response) => {
	const { username, password } = req.body;

	logAction('APP_REGISTER_ATTEMPT', {
		description: 'User attempted to register app account',
		username: username,
		usernameLength: username?.length,
		passwordLength: password?.length,
		hasUsername: !!username,
		hasPassword: !!password,
		emailDomain: username?.includes('@') ? username.split('@')[1] : undefined,
		isDomainEmail: username ? validateDomainEmail(username) : false
	}, req);

	if (!username || !password) {
		logAction('APP_REGISTER_FAILED', {
			reason: 'Missing username or password',
			hasUsername: !!username,
			hasPassword: !!password
		}, req, res);
		return res.status(400).json({ error: "Username and password are required" });
	}

	if (typeof username !== 'string' || typeof password !== 'string') {
		logAction('APP_REGISTER_FAILED', {
			reason: 'Invalid data types',
			usernameType: typeof username,
			passwordType: typeof password
		}, req, res);
		return res.status(400).json({ error: "Username and password must be strings" });
	}

	const isValidDomain = validateDomainEmail(username);
	logAction('APP_REGISTER_BLOCKED', {
		reason: 'Registration blocked - email validation',
		username: username,
		isValidDomainEmail: isValidDomain,
		emailDomain: username.split('@')[1]
	}, req, res);

	// Block all emails since they realistically can't have an @domain.com email
	return res.status(404).json({ error: "Email address not found" });
});

// --- Main App User Login Endpoint ---
app.post('/api/app/login', (req: Request, res: Response) => {
	const { username, password } = req.body;

	logAction('APP_LOGIN_ATTEMPT', {
		description: 'User attempted app login',
		username: username,
		usernameLength: username?.length,
		passwordLength: password?.length,
		hasUsername: !!username,
		hasPassword: !!password,
		emailDomain: username?.includes('@') ? username.split('@')[1] : undefined
	}, req);

	if (!username || !password) {
		logAction('APP_LOGIN_FAILED', {
			reason: 'Missing username or password',
			hasUsername: !!username,
			hasPassword: !!password
		}, req, res);
		return res.status(400).json({ error: "Username and password are required" });
	}

	const user = mainAppUsers.find(u => u.username === username && u.password === password);
	
	if (!user) {
		const usernameExists = mainAppUsers.some(u => u.username === username);
		logAction('APP_LOGIN_FAILED', {
			reason: 'Invalid credentials',
			username: username,
			usernameExists: usernameExists,
			attemptedPasswordMatch: false,
			userFound: false
		}, req, res);
		return res.status(401).json({ error: "Invalid credentials" });
	}

	const token = jwt.sign({ userId: user.userId }, JWT_SECRET);

	res.cookie('token-for-prod', token, {
		httpOnly: true,
		secure: false,
		sameSite: 'lax',
	});

	logAction('APP_LOGIN_SUCCESS', {
		description: 'App login successful',
		username: username,
		userId: user.userId,
		userRole: user.role,
		userEnabled: user.enabled,
		tokenGenerated: true,
		cookieSet: 'token-for-prod',
		hasFlag: 'flag' in user
	}, req, res);

	return res.json({ message: "Login successful" });
});

// Extend Request interface to include user property
interface AuthRequest extends Request {
	user?: any;
	cookies: any;
	body: any;
	query: any;
	params: any;
	path: string;
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
	let tokenType = 'token-for-prod';
	if (!token) {
		token = req.cookies['dev-token'];
		tokenType = 'dev-token';
	}

	if (!token) {
		logAction('AUTH_FAILED', {
			description: 'Authentication attempt failed - no token present',
			endpoint: req.path,
			hasTokenForProd: !!req.cookies['token-for-prod'],
			hasDevToken: !!req.cookies['dev-token'],
			allCookies: Object.keys(req.cookies || {})
		}, req, res);
		return res.status(401).json({ error: "Authentication required" });
	}

	try {
		const decoded = jwt.verify(token, JWT_SECRET) as any;
		req.user = decoded;
		logAction('AUTH_SUCCESS', {
			description: 'Token validation successful',
			endpoint: req.path,
			tokenType: tokenType,
			userId: decoded.userId,
			tokenLength: token.length
		}, req);
		next();
	} catch (err) {
		logAction('AUTH_FAILED', {
			description: 'Token validation failed',
			endpoint: req.path,
			tokenType: tokenType,
			tokenLength: token.length,
			error: err instanceof Error ? err.message : 'Unknown error',
			hasToken: true
		}, req, res);
		return res.status(401).json({ error: "Invalid or expired token" });
	}
}

// --- /api/me endpoint (only for appUsers) ---
app.get('/api/me', authenticateJWT, (req: AuthRequest, res: Response) => {
	const { userId } = req.user;
	
	logAction('API_ME_REQUEST', {
		description: 'User requested their profile information',
		requestedUserId: userId,
		tokenType: req.cookies['token-for-prod'] ? 'token-for-prod' : 'dev-token'
	}, req);

	const user = mainAppUsers.find(u => u.userId === userId);

	if (!user) {
		logAction('API_ME_FAILED', {
			reason: 'User not found in mainAppUsers',
			requestedUserId: userId,
			userExists: false
		}, req, res);
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
		logAction('API_ME_SUCCESS', {
			description: 'User profile retrieved - flag included',
			userId: user.userId,
			username: user.username,
			role: user.role,
			enabled: user.enabled,
			flagIncluded: true
		}, req, res);
	} else {
		logAction('API_ME_SUCCESS', {
			description: 'User profile retrieved - no flag',
			userId: user.userId,
			username: user.username,
			role: user.role,
			enabled: user.enabled,
			flagIncluded: false
		}, req, res);
	}

	res.json(response);
});

// --- /api/admin/me endpoint (only for adminUsers) ---
app.get('/api/admin/me', authenticateJWT, (req: AuthRequest, res: Response) => {
	const { userId } = req.user;
	
	logAction('API_ADMIN_ME_REQUEST', {
		description: 'User requested admin profile information',
		requestedUserId: userId,
		tokenType: req.cookies['dev-token'] ? 'dev-token' : 'token-for-prod'
	}, req);

	const user = adminAppUsers.find(u => u.userId === userId);

	if (!user) {
		logAction('API_ADMIN_ME_FAILED', {
			reason: 'User not found in adminAppUsers',
			requestedUserId: userId,
			userExists: false,
			isMainAppUser: mainAppUsers.some(u => u.userId === userId)
		}, req, res);
		return res.status(403).json({ error: "Forbidden" });
	}

	logAction('API_ADMIN_ME_SUCCESS', {
		description: 'Admin profile retrieved',
		userId: user.userId,
		username: user.username
	}, req, res);

	res.json({
		userId: user.userId,
		username: user.username,
		authenticated: true
	});
});

// --- POST to get all app users (vuln here, only checks if you're logged in, not if you're an admin) ---
app.post('/api/users', authenticateJWT, (req: AuthRequest, res: Response) => {
	const userId = req.user.userId;
	
	logAction('API_USERS_REQUEST', {
		description: 'User attempted to retrieve all users list',
		requestedByUserId: userId,
		requestBody: req.body
	}, req);

	const user = mainAppUsers.find(u => u.userId === userId && u.role === 'admin');
	if (!user) {
		const requestingUser = mainAppUsers.find(u => u.userId === userId);
		logAction('API_USERS_FAILED', {
			reason: 'Unauthorized - not an admin',
			requestedByUserId: userId,
			requestingUserRole: requestingUser?.role || 'not found',
			requestingUserExists: !!requestingUser,
			isAdmin: false
		}, req, res);
		return res.status(403).json({ error: "Unauthorized, need an admin account to check this." });
	}
	
	// Only show emails, userIds, roles, and enabled status (no flag property)
	const users = mainAppUsers.map(u => ({
		userId: u.userId,
		username: u.username,
		role: u.role,
		enabled: u.enabled
	}));
	
	logAction('API_USERS_SUCCESS', {
		description: 'User list retrieved successfully',
		requestedByUserId: userId,
		requestedByUsername: user.username,
		userCount: users.length,
		usersReturned: users.length
	}, req, res);
	
	res.json({ users });
});

// --- /api endpoint - Lists all available endpoints ---
app.get('/api', (req: Request, res: Response) => {
	logAction('API_ENDPOINTS_LIST', {
		description: 'User requested API endpoints list',
		hasAuth: !!(req.cookies['token-for-prod'] || req.cookies['dev-token'])
	}, req, res);

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
	const requestingUserId = req.user.userId;
	
	logAction('API_USER_BY_ID_REQUEST', {
		description: 'User attempted to retrieve user by ID',
		requestedUserId: requestingUserId,
		targetUserId: idParam,
		requestingUserRole: mainAppUsers.find(u => u.userId === requestingUserId)?.role
	}, req);

	if (!idParam) {
		logAction('API_USER_BY_ID_FAILED', {
			reason: 'Missing user ID parameter',
			requestedUserId: requestingUserId
		}, req, res);
		return res.status(400).json({ error: "Invalid user ID" });
	}
	const userId = parseInt(idParam);
	if (isNaN(userId)) {
		logAction('API_USER_BY_ID_FAILED', {
			reason: 'Invalid user ID format',
			requestedUserId: requestingUserId,
			providedId: idParam
		}, req, res);
		return res.status(400).json({ error: "Invalid user ID" });
	}
	const user = mainAppUsers.find(u => u.userId === userId);
	if (!user) {
		logAction('API_USER_BY_ID_FAILED', {
			reason: 'User not found',
			requestedUserId: requestingUserId,
			targetUserId: userId,
			userExists: false
		}, req, res);
		return res.status(404).json({ error: "User not found" });
	}
	
	logAction('API_USER_BY_ID_SUCCESS', {
		description: 'User retrieved by ID',
		requestedUserId: requestingUserId,
		targetUserId: userId,
		targetUsername: user.username,
		targetRole: user.role,
		targetEnabled: user.enabled
	}, req, res);
	
	// Intentionally don't show flag property here
	res.json({ userId: user.userId, username: user.username, role: user.role, enabled: user.enabled });
});

app.put('/api/user/:id', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_USER_UPDATE_ATTEMPT', {
		description: 'User attempted to update another user',
		requestedUserId: requestingUserId,
		targetUserId: req.params.id,
		requestBody: req.body
	}, req, res);
	res.status(403).json({ error: "Insufficient permissions. Admin role required." });
});

app.delete('/api/user/:id', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_USER_DELETE_ATTEMPT', {
		description: 'User attempted to delete another user',
		requestedUserId: requestingUserId,
		targetUserId: req.params.id
	}, req, res);
	res.status(403).json({ error: "Insufficient permissions. Admin role required." });
});

app.post('/api/auth/refresh', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_AUTH_REFRESH_ATTEMPT', {
		description: 'User attempted to refresh token',
		requestedUserId: requestingUserId
	}, req, res);
	res.status(501).json({ error: "Token refresh not implemented yet" });
});

app.post('/api/auth/logout', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_AUTH_LOGOUT', {
		description: 'User logged out',
		requestedUserId: requestingUserId,
		username: mainAppUsers.find(u => u.userId === requestingUserId)?.username || adminAppUsers.find(u => u.userId === requestingUserId)?.username
	}, req, res);
	// Clear both possible cookies
	res.clearCookie('token-for-prod', { path: '/' });
	res.clearCookie('dev-token', { path: '/' });
	res.json({ message: "Logged out successfully" });
});

app.get('/api/users/search', authenticateJWT, (req: AuthRequest, res: Response) => {
	const query = req.query.q as string;
	const requestingUserId = req.user.userId;
	
	logAction('API_USERS_SEARCH_REQUEST', {
		description: 'User attempted to search users',
		requestedUserId: requestingUserId,
		searchQuery: query,
		queryLength: query?.length
	}, req);

	if (!query) {
		logAction('API_USERS_SEARCH_FAILED', {
			reason: 'Missing search query',
			requestedUserId: requestingUserId
		}, req, res);
		return res.status(400).json({ error: "Search query required" });
	}
	// Only return basic info, no flag
	const results = mainAppUsers
		.filter(u => u.username.toLowerCase().includes(query.toLowerCase()))
		.map(u => ({ userId: u.userId, username: u.username, role: u.role }));
	
	logAction('API_USERS_SEARCH_SUCCESS', {
		description: 'User search completed',
		requestedUserId: requestingUserId,
		searchQuery: query,
		resultCount: results.length
	}, req, res);
	
	res.json({ results, count: results.length });
});

app.get('/api/users/:id/posts', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_USER_POSTS_REQUEST', {
		description: 'User attempted to retrieve user posts',
		requestedUserId: requestingUserId,
		targetUserId: req.params.id
	}, req, res);
	res.status(404).json({ error: "Posts feature not implemented" });
});

app.get('/api/admin/users', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_ADMIN_USERS_REQUEST', {
		description: 'User attempted to access admin users list',
		requestedUserId: requestingUserId,
		requestingUserRole: mainAppUsers.find(u => u.userId === requestingUserId)?.role
	}, req, res);
	res.status(403).json({ error: "Admin access required. Your role does not have sufficient permissions." });
});

app.get('/api/admin/stats', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_ADMIN_STATS_REQUEST', {
		description: 'User attempted to access admin stats',
		requestedUserId: requestingUserId,
		requestingUserRole: mainAppUsers.find(u => u.userId === requestingUserId)?.role
	}, req, res);
	res.status(403).json({ error: "Admin access required. Your role does not have sufficient permissions." });
});

app.post('/api/admin/settings', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_ADMIN_SETTINGS_REQUEST', {
		description: 'User attempted to update admin settings',
		requestedUserId: requestingUserId,
		requestBody: req.body,
		requestingUserRole: mainAppUsers.find(u => u.userId === requestingUserId)?.role
	}, req, res);
	res.status(403).json({ error: "Admin access required. Your role does not have sufficient permissions." });
});

app.get('/api/admin/logs', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_ADMIN_LOGS_REQUEST', {
		description: 'User attempted to access admin logs',
		requestedUserId: requestingUserId,
		requestingUserRole: mainAppUsers.find(u => u.userId === requestingUserId)?.role
	}, req, res);
	res.status(403).json({ error: "Admin access required" });
});

app.post('/api/admin/ban', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_ADMIN_BAN_REQUEST', {
		description: 'User attempted to ban a user',
		requestedUserId: requestingUserId,
		requestBody: req.body,
		requestingUserRole: mainAppUsers.find(u => u.userId === requestingUserId)?.role
	}, req, res);
	res.status(403).json({ error: "Admin access required" });
});

app.get('/api/admin/reports', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_ADMIN_REPORTS_REQUEST', {
		description: 'User attempted to access admin reports',
		requestedUserId: requestingUserId,
		requestingUserRole: mainAppUsers.find(u => u.userId === requestingUserId)?.role
	}, req, res);
	res.status(403).json({ error: "Admin access required" });
});

app.get('/api/data/export', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_DATA_EXPORT_REQUEST', {
		description: 'User attempted to export data',
		requestedUserId: requestingUserId
	}, req, res);
	res.status(503).json({ error: "Data export service temporarily unavailable" });
});

app.post('/api/data/import', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_DATA_IMPORT_REQUEST', {
		description: 'User attempted to import data',
		requestedUserId: requestingUserId,
		requestBody: Object.keys(req.body).length > 0 ? 'present' : 'empty',
		requestingUserRole: mainAppUsers.find(u => u.userId === requestingUserId)?.role
	}, req, res);
	res.status(403).json({ error: "Admin access required for data import" });
});

app.get('/api/data/backup', authenticateJWT, (req: AuthRequest, res: Response) => {
	const requestingUserId = req.user.userId;
	logAction('API_DATA_BACKUP_REQUEST', {
		description: 'User attempted to access data backup',
		requestedUserId: requestingUserId,
		requestingUserRole: mainAppUsers.find(u => u.userId === requestingUserId)?.role
	}, req, res);
	res.status(403).json({ error: "Admin access required for backups" });
});

app.get('/api/health', (req: Request, res: Response) => {
	logAction('API_HEALTH_CHECK', {
		description: 'Health check endpoint accessed'
	}, req, res);
	res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

app.get('/api/version', (req: Request, res: Response) => {
	logAction('API_VERSION_REQUEST', {
		description: 'API version endpoint accessed'
	}, req, res);
	res.json({ version: "1.0.0", build: "2024-01-15" });
});

app.get('/api/docs', (req: Request, res: Response) => {
	logAction('API_DOCS_REQUEST', {
		description: 'API docs endpoint accessed'
	}, req, res);
	res.json({
		message: "API documentation is available at /api",
		note: "Use GET /api to see all available endpoints"
	});
});

app.get('/api/config', (req: Request, res: Response) => {
	logAction('API_CONFIG_REQUEST', {
		description: 'API config endpoint accessed'
	}, req, res);
	res.json({
		message: "Configuration endpoint is disabled",
		reason: "Security policy"
	});
});

app.get('/api/status', (req: Request, res: Response) => {
	logAction('API_STATUS_REQUEST', {
		description: 'API status endpoint accessed'
	}, req, res);
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
