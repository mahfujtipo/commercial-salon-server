import express from 'express';
import { MongoClient, ObjectId } from 'mongodb';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import 'dotenv/config';

const app = express();
const port = process.env.PORT || 8000;
const isProduction = process.env.NODE_ENV === 'production';

/* -------------------------------------------------------------------------- */
/*                              Env validation                                */
/* -------------------------------------------------------------------------- */

if (!process.env.CLIENT_URI) {
    throw new Error('CLIENT_URI is missing from environment variables');
}

if (!process.env.MONGODB_URI) {
    throw new Error('MONGODB_URI is missing from environment variables');
}

const AUTH_URL = (process.env.BETTER_AUTH_URL || process.env.CLIENT_URI).replace(/\/$/, '');

/* -------------------------------------------------------------------------- */
/*                                Middlewares                                 */
/* -------------------------------------------------------------------------- */

app.set('trust proxy', 1);

app.use(helmet());

app.use(cors({
    origin: process.env.CLIENT_URI,
    credentials: true
}));

app.use(express.json({ limit: '1mb' }));

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 500,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many requests, please try again later', errors: null }
});

const writeLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many requests, please slow down', errors: null }
});

/* -------------------------------------------------------------------------- */
/*                                Base routes                                 */
/* -------------------------------------------------------------------------- */

app.get('/', (req, res) => {
    res.send('SalonBook Backend is running successfully!');
});

const router = express.Router();

/* -------------------------------------------------------------------------- */
/*                               Small helpers                                */
/* -------------------------------------------------------------------------- */

class ApiError extends Error {
    constructor(status, message, errors = null) {
        super(message);
        this.status = status;
        this.errors = errors;
    }
}

const sendSuccess = (res, data = null, message = 'Success', status = 200, extra = {}) =>
    res.status(status).json({ success: true, message, data, ...extra });

const asString = (value) => (typeof value === 'string' ? value.trim() : '');

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const getPagination = (query, defaultLimit = 9, maxLimit = 50) => {
    const page = Math.max(parseInt(query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(query.limit, 10) || defaultLimit, 1), maxLimit);
    return { page, limit, skip: (page - 1) * limit };
};

const pageMeta = (total, page, limit) => ({
    total,
    page,
    limit,
    totalPages: Math.max(Math.ceil(total / limit), 1)
});

function isValidObjectId(id) {
    return typeof id === 'string' && /^[a-fA-F0-9]{24}$/.test(id) && ObjectId.isValid(id);
}

const validateObjectId = (paramName = 'id') => (req, res, next) => {
    if (!isValidObjectId(req.params[paramName])) {
        return next(new ApiError(400, `Invalid ${paramName}`));
    }
    next();
};

/* ----------------------------- Date/time helpers --------------------------- */

// Salon time zone: Bangladesh (UTC+6), same as your previous project
function getBookingDateTime(date, time) {
    return new Date(`${date}T${time}:00+06:00`);
}

function isValidBookingDate(date) {
    if (typeof date !== 'string') return false;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return false;

    const parsedDate = new Date(`${date}T00:00:00Z`);

    return (
        !isNaN(parsedDate.getTime()) &&
        parsedDate.toISOString().slice(0, 10) === date
    );
}

// Simple predefined list of salon time slots
const TIME_SLOTS = [
    '09:00', '10:00', '11:00', '12:00',
    '14:00', '15:00', '16:00', '17:00'
];

/* -------------------------------------------------------------------------- */
/*                               MongoDB setup                                */
/* -------------------------------------------------------------------------- */

const client = new MongoClient(process.env.MONGODB_URI);

let connectionPromise;

export async function connectToMongoDB() {
    if (!connectionPromise) {
        connectionPromise = client.connect().catch((err) => {
            connectionPromise = null;
            throw err;
        });
    }

    try {
        await connectionPromise;
        console.log('You successfully connected to MongoDB!');
        return client;
    } catch (err) {
        console.error('MongoDB connection failed:', err);
        throw err;
    }
}

const mongoClient = await connectToMongoDB();

const db = mongoClient.db('salon-database');

// Better Auth's own user collection (it manages auth data; we extend it with role/isBlocked/phone)
const usersCollection = db.collection(process.env.USER_COLLECTION || 'user');
const servicesCollection = db.collection('services');
const appointmentsCollection = db.collection('appointments');

// Indexes (safe to run on every start)
try {
    // Database-level double-booking protection:
    // slotKey exists ONLY on pending/confirmed appointments (removed on cancel),
    // and a sparse unique index means two active appointments can never share a slot.
    await appointmentsCollection.createIndex({ slotKey: 1 }, { unique: true, sparse: true });
    await appointmentsCollection.createIndex({ customerId: 1, createdAt: -1 });
    await appointmentsCollection.createIndex({ status: 1, createdAt: -1 });
    await servicesCollection.createIndex({ status: 1, category: 1 });
    await servicesCollection.createIndex({ price: 1 });
} catch (err) {
    console.error('Index creation failed:', err);
}

/* -------------------------------------------------------------------------- */
/*                           JWT / Auth middlewares                           */
/* -------------------------------------------------------------------------- */

const JWKS = createRemoteJWKSet(new URL(`${AUTH_URL}/api/auth/jwks`));

const jwtOptions = {};
if (process.env.JWT_ISSUER) jwtOptions.issuer = process.env.JWT_ISSUER;
if (process.env.JWT_AUDIENCE) jwtOptions.audience = process.env.JWT_AUDIENCE;

// JWT Verification Middleware (same logic as your index.js)
// + loads the CURRENT role / blocked status from MongoDB (never trusts the token for role)
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            success: false,
            message: 'Unauthorized',
            errors: null
        });
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Unauthorized',
            errors: null
        });
    }

    let payload;

    try {
        const result = await jwtVerify(token, JWKS, jwtOptions);
        payload = result.payload;
    } catch (error) {
        console.error('JWT verification error:', error.code || error.message);

        return res.status(401).json({
            success: false,
            message: 'Invalid or expired token',
            errors: null
        });
    }

    if (!payload.email || typeof payload.email !== 'string') {
        return res.status(401).json({
            success: false,
            message: 'Invalid user token',
            errors: null
        });
    }

    try {
        const dbUser = await usersCollection.findOne({
            email: payload.email.toLowerCase()
        });

        if (!dbUser) {
            return res.status(401).json({
                success: false,
                message: 'User account not found',
                errors: null
            });
        }

        req.tokenPayload = payload;
        req.user = {
            _id: dbUser._id,
            name: dbUser.name,
            email: dbUser.email,
            image: dbUser.image || '',
            phone: dbUser.phone || '',
            role: dbUser.role === 'admin' ? 'admin' : 'customer',
            isBlocked: dbUser.isBlocked === true
        };

        next();
    } catch (err) {
        next(err);
    }
};

const requireAdmin = (req, res, next) => {
    if (req.user?.role !== 'admin') {
        return next(new ApiError(403, 'Forbidden: admin access only'));
    }
    next();
};

const requireActiveUser = (req, res, next) => {
    if (req.user?.isBlocked) {
        return next(new ApiError(403, 'Your account has been blocked. Please contact the salon.'));
    }
    next();
};

const requireCustomer = (req, res, next) => {
    if (req.user?.role !== 'customer') {
        return next(new ApiError(403, 'Forbidden: customer access only'));
    }
    if (req.user.isBlocked) {
        return next(new ApiError(403, 'Your account has been blocked. Please contact the salon.'));
    }
    next();
};

/* ================================= USERS ================================== */

const safeUser = (user) => ({
    _id: user._id,
    name: user.name,
    email: user.email,
    image: user.image || '',
    phone: user.phone || '',
    role: user.role === 'admin' ? 'admin' : 'customer',
    isBlocked: user.isBlocked === true,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
});

async function findUserById(id) {
    // Better Auth's Mongo adapter stores _id as ObjectId; fall back to string `id` field just in case
    return (
        (await usersCollection.findOne({ _id: new ObjectId(id) })) ||
        (await usersCollection.findOne({ id }))
    );
}

// GET /users/me  (allowed even if blocked, so the frontend can show the blocked state)
router.get('/users/me', verifyToken, async (req, res) => {
    const user = await usersCollection.findOne({ _id: req.user._id });
    sendSuccess(res, safeUser(user), 'Profile fetched successfully');
});

// PATCH /users/me  (only name, image, phone allowed -> no mass assignment)
router.patch('/users/me', verifyToken, requireActiveUser, async (req, res) => {
    const updates = {};
    const errors = {};

    if (req.body.name !== undefined) {
        const name = asString(req.body.name);
        if (name.length < 2 || name.length > 80) errors.name = 'Name must be 2-80 characters';
        else updates.name = name;
    }

    if (req.body.image !== undefined) {
        const image = asString(req.body.image);
        if (image) {
            try {
                const u = new URL(image);
                if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
            } catch {
                errors.image = 'Image must be a valid http(s) URL';
            }
        }
        if (!errors.image) updates.image = image;
    }

    if (req.body.phone !== undefined) {
        const phone = asString(req.body.phone);
        if (phone && !/^\+?[\d\s-]{6,20}$/.test(phone)) errors.phone = 'Invalid phone number';
        else updates.phone = phone;
    }

    if (Object.keys(errors).length > 0) {
        throw new ApiError(400, 'Validation failed', errors);
    }

    if (Object.keys(updates).length === 0) {
        throw new ApiError(400, 'No valid fields provided for update');
    }

    updates.updatedAt = new Date();

    await usersCollection.updateOne({ _id: req.user._id }, { $set: updates });

    const updated = await usersCollection.findOne({ _id: req.user._id });
    sendSuccess(res, safeUser(updated), 'Profile updated successfully');
});

// GET /users  (admin) -> all customers
router.get('/users', verifyToken, requireAdmin, async (req, res) => {
    const { page, limit, skip } = getPagination(req.query, 10, 100);
    const filter = { role: { $ne: 'admin' } };

    const search = asString(req.query.search);
    if (search) {
        const regex = new RegExp(escapeRegex(search), 'i');
        filter.$or = [{ name: regex }, { email: regex }];
    }

    if (req.query.isBlocked === 'true') filter.isBlocked = true;
    if (req.query.isBlocked === 'false') filter.isBlocked = { $ne: true };

    const [users, total] = await Promise.all([
        usersCollection.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
        usersCollection.countDocuments(filter)
    ]);

    sendSuccess(res, users.map(safeUser), 'Customers fetched successfully', 200, {
        pagination: pageMeta(total, page, limit)
    });
});

// GET /users/:id (admin)
router.get('/users/:id', verifyToken, requireAdmin, validateObjectId('id'), async (req, res) => {
    const user = await findUserById(req.params.id);
    if (!user) throw new ApiError(404, 'User not found');
    sendSuccess(res, safeUser(user), 'User fetched successfully');
});

async function setBlockedStatus(req, res, blocked) {
    const target = await findUserById(req.params.id);

    if (!target) throw new ApiError(404, 'User not found');

    if (target.role === 'admin') {
        throw new ApiError(403, 'Admin accounts cannot be blocked or unblocked');
    }

    if (String(target._id) === String(req.user._id)) {
        throw new ApiError(400, 'You cannot block yourself');
    }

    await usersCollection.updateOne(
        { _id: target._id },
        { $set: { isBlocked: blocked, updatedAt: new Date() } }
    );

    const updated = await usersCollection.findOne({ _id: target._id });
    sendSuccess(res, safeUser(updated), blocked ? 'User blocked successfully' : 'User unblocked successfully');
}

router.patch('/users/:id/block', verifyToken, requireAdmin, validateObjectId('id'), (req, res) =>
    setBlockedStatus(req, res, true)
);

router.patch('/users/:id/unblock', verifyToken, requireAdmin, validateObjectId('id'), (req, res) =>
    setBlockedStatus(req, res, false)
);

/* -------------------------------------------------------------------------- */
/*                         Mount router & error handling                      */
/* -------------------------------------------------------------------------- */

app.use('/api/v1', apiLimiter, router);

// 404 for unknown routes
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: `Route not found: ${req.method} ${req.originalUrl}`,
        errors: null
    });
});

// Centralized error handler
app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);

    if (err instanceof multer.MulterError) {
        const message =
            err.code === 'LIMIT_FILE_SIZE' ? 'Image must be 5MB or smaller' : 'Invalid file upload';
        return res.status(400).json({ success: false, message, errors: null });
    }

    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({ success: false, message: 'Invalid JSON body', errors: null });
    }

    if (err instanceof ApiError) {
        return res.status(err.status).json({
            success: false,
            message: err.message,
            errors: err.errors
        });
    }

    console.error('Unhandled error:', err);

    res.status(500).json({
        success: false,
        message: isProduction ? 'Internal server error' : err.message,
        errors: null
    });
});

if (process.env.VERCEL !== '1') {
    app.listen(port, () => {
        console.log(`Server is running smoothly on port ${port}`);
    });
}

export default app;
