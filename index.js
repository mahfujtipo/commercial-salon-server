import express from 'express';
import { randomUUID } from 'node:crypto';
import { MongoClient, ObjectId } from 'mongodb';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import Stripe from 'stripe';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import 'dotenv/config';

const app = express();
const port = process.env.PORT || 8000;
const isProduction = process.env.NODE_ENV === 'production';

if (!process.env.CLIENT_URI) {
    throw new Error('CLIENT_URI is missing from environment variables');
}

if (!process.env.MONGODB_URI) {
    throw new Error('MONGODB_URI is missing from environment variables');
}

const AUTH_URL = (process.env.BETTER_AUTH_URL || process.env.CLIENT_URI).replace(/\/$/, '');

// Stripe is optional at startup so the rest of the API still works without keys.
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;
const PAYMENT_CURRENCY = (process.env.PAYMENT_CURRENCY || 'usd').toLowerCase();

app.set('trust proxy', 1);

app.use(helmet());

app.use(cors({
    origin: process.env.CLIENT_URI,
    credentials: true
}));
app.use('/api/v1/webhooks/stripe', express.raw({ type: 'application/json' }));

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
app.get('/', (req, res) => {
    res.send('SalonBook Backend is running successfully!');
});

const router = express.Router();
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

const db = mongoClient.db(process.env.DB_NAME || 'SalonBook');

// Better Auth's own user collection (it manages auth data; we extend it with role/isBlocked/phone)
const usersCollection = db.collection(process.env.USER_COLLECTION || 'user');
const servicesCollection = db.collection('services');
const appointmentsCollection = db.collection('appointments');
const transactionsCollection = db.collection('transactions');

// Indexes (safe to run on every start)
try {
    // Database-level double-booking protection:
    // slotKey exists ONLY on pending/confirmed appointments (removed on cancel),
    // and a sparse unique index means two active appointments can never share a slot.
    await appointmentsCollection.createIndex({ slotKey: 1 }, { unique: true, sparse: true });
    await appointmentsCollection.createIndex({ customerId: 1, createdAt: -1 });
    await appointmentsCollection.createIndex({ status: 1, createdAt: -1 });
    // One transaction per Stripe Checkout session (also makes webhook retries idempotent)
    await transactionsCollection.createIndex({ stripeSessionId: 1 }, { unique: true });
    await transactionsCollection.createIndex({ customerId: 1, createdAt: -1 });
    await servicesCollection.createIndex({ status: 1, category: 1 });
    await servicesCollection.createIndex({ price: 1 });
} catch (err) {
    console.error('Index creation failed:', err);
}
const JWKS = createRemoteJWKSet(new URL(`${AUTH_URL}/api/auth/jwks`));

const jwtOptions = {};
if (process.env.BETTER_AUTH_ISSUER || process.env.JWT_ISSUER) jwtOptions.issuer = process.env.BETTER_AUTH_ISSUER || process.env.JWT_ISSUER;
if (process.env.BETTER_AUTH_AUDIENCE || process.env.JWT_AUDIENCE) jwtOptions.audience = process.env.BETTER_AUTH_AUDIENCE || process.env.JWT_AUDIENCE;

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
    if (req.user?.isBlocked) {
        return next(new ApiError(403, 'Your account has been blocked. Please contact the salon.'));
    }

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

/* ================================ SERVICES ================================ */

const SERVICE_STATUSES = ['active', 'inactive'];

function validateServiceInput(body, { partial = false } = {}) {
    const data = {};
    const errors = {};
    const has = (key) => body[key] !== undefined;

    if (!partial || has('serviceName')) {
        const v = asString(body.serviceName);
        if (v.length < 2 || v.length > 100) errors.serviceName = 'Service name must be 2-100 characters';
        else data.serviceName = v;
    }

    if (!partial || has('category')) {
        const v = asString(body.category);
        if (v.length < 2 || v.length > 50) errors.category = 'Category must be 2-50 characters';
        else data.category = v;
    }

    if (!partial || has('description')) {
        const v = asString(body.description);
        if (v.length < 10 || v.length > 2000) errors.description = 'Description must be 10-2000 characters';
        else data.description = v;
    }

    if (!partial || has('price')) {
        const v = Number(body.price);
        if (!Number.isFinite(v) || v <= 0) errors.price = 'Price must be a positive number';
        else data.price = v;
    }

    if (!partial || has('duration')) {
        const v = Number(body.duration);
        if (!Number.isInteger(v) || v <= 0) errors.duration = 'Duration must be a positive whole number (minutes)';
        else data.duration = v;
    }

    if (!partial || has('image')) {
        const v = asString(body.image);
        try {
            const u = new URL(v);
            if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
            data.image = v;
        } catch {
            errors.image = 'A valid image URL is required (upload the image first)';
        }
    }

    if (has('status')) {
        if (!SERVICE_STATUSES.includes(body.status)) errors.status = 'Status must be active or inactive';
        else data.status = body.status;
    } else if (!partial) {
        data.status = 'active';
    }

    return { data, errors };
}

function buildServiceFilter(query, { adminView = false } = {}) {
    const filter = {};

    if (adminView) {
        if (SERVICE_STATUSES.includes(query.status)) filter.status = query.status;
    } else {
        filter.status = 'active';
    }

    const search = asString(query.search);
    if (search) filter.serviceName = { $regex: escapeRegex(search), $options: 'i' };

    const category = asString(query.category);
    if (category) filter.category = category;

    const minPrice = Number(query.minPrice);
    const maxPrice = Number(query.maxPrice);
    const priceFilter = {};
    if (query.minPrice !== undefined && query.minPrice !== '' && Number.isFinite(minPrice)) priceFilter.$gte = minPrice;
    if (query.maxPrice !== undefined && query.maxPrice !== '' && Number.isFinite(maxPrice)) priceFilter.$lte = maxPrice;
    if (Object.keys(priceFilter).length) filter.price = priceFilter;

    return filter;
}

function buildServiceSort(sort) {
    if (sort === 'price_asc') return { price: 1, _id: 1 };
    if (sort === 'price_desc') return { price: -1, _id: 1 };
    return { createdAt: -1, _id: 1 };
}

async function listServices(req, res, adminView) {
    const { page, limit, skip } = getPagination(req.query, 9, 50);
    const filter = buildServiceFilter(req.query, { adminView });
    const sort = buildServiceSort(req.query.sort);

    const [services, total] = await Promise.all([
        servicesCollection.find(filter).sort(sort).skip(skip).limit(limit).toArray(),
        servicesCollection.countDocuments(filter)
    ]);

    sendSuccess(res, services, 'Services fetched successfully', 200, {
        pagination: pageMeta(total, page, limit)
    });
}

// GET /services  (public, active only)
router.get('/services', (req, res) => listServices(req, res, false));

// GET /services/featured (public) -> latest active services
router.get('/services/featured', async (req, res) => {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 6, 1), 20);

    const services = await servicesCollection
        .find({ status: 'active' })
        .sort({ createdAt: -1 })
        .limit(limit)
        .toArray();

    sendSuccess(res, services, 'Featured services fetched successfully');
});

// GET /services/categories (public)
router.get('/services/categories', async (req, res) => {
    const categories = await servicesCollection
        .aggregate([
            { $match: { status: 'active' } },
            { $group: { _id: '$category', count: { $sum: 1 } } },
            { $sort: { _id: 1 } },
            { $project: { _id: 0, category: '$_id', count: 1 } }
        ])
        .toArray();

    sendSuccess(res, categories, 'Categories fetched successfully');
});

// GET /services/admin/all (admin: active + inactive)
router.get('/services/admin/all', verifyToken, requireAdmin, (req, res) => listServices(req, res, true));

// GET /services/admin/:id (admin: active or inactive, for edit page)
router.get('/services/admin/:id', verifyToken, requireAdmin, validateObjectId('id'), async (req, res) => {
    const service = await servicesCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!service) throw new ApiError(404, 'Service not found');
    sendSuccess(res, service, 'Service fetched successfully');
});

// GET /services/:id (public)
router.get('/services/:id', validateObjectId('id'), async (req, res) => {
    const service = await servicesCollection.findOne({
        _id: new ObjectId(req.params.id),
        status: 'active'
    });

    if (!service) throw new ApiError(404, 'Service not found or no longer available');

    sendSuccess(res, service, 'Service fetched successfully');
});

// POST /services (admin)
router.post('/services', verifyToken, requireAdmin, async (req, res) => {
    const { data, errors } = validateServiceInput(req.body);

    if (Object.keys(errors).length > 0) {
        throw new ApiError(400, 'Validation failed', errors);
    }

    const now = new Date();
    const result = await servicesCollection.insertOne({ ...data, createdAt: now, updatedAt: now });

    const created = await servicesCollection.findOne({ _id: result.insertedId });
    sendSuccess(res, created, 'Service created successfully', 201);
});

// PATCH /services/:id/status (admin)  -- before PATCH /services/:id for clarity
router.patch('/services/:id/status', verifyToken, requireAdmin, validateObjectId('id'), async (req, res) => {
    if (!SERVICE_STATUSES.includes(req.body.status)) {
        throw new ApiError(400, 'Status must be active or inactive');
    }

    const updated = await servicesCollection.findOneAndUpdate(
        { _id: new ObjectId(req.params.id) },
        { $set: { status: req.body.status, updatedAt: new Date() } },
        { returnDocument: 'after' }
    );

    if (!updated) throw new ApiError(404, 'Service not found');

    sendSuccess(res, updated, `Service ${req.body.status === 'active' ? 'activated' : 'deactivated'} successfully`);
});

// PATCH /services/:id (admin)
router.patch('/services/:id', verifyToken, requireAdmin, validateObjectId('id'), async (req, res) => {
    const { data, errors } = validateServiceInput(req.body, { partial: true });

    if (Object.keys(errors).length > 0) {
        throw new ApiError(400, 'Validation failed', errors);
    }

    if (Object.keys(data).length === 0) {
        throw new ApiError(400, 'No valid fields provided for update');
    }

    const updated = await servicesCollection.findOneAndUpdate(
        { _id: new ObjectId(req.params.id) },
        { $set: { ...data, updatedAt: new Date() } },
        { returnDocument: 'after' }
    );

    if (!updated) throw new ApiError(404, 'Service not found');

    sendSuccess(res, updated, 'Service updated successfully');
});

// DELETE /services/:id (admin)
router.delete('/services/:id', verifyToken, requireAdmin, validateObjectId('id'), async (req, res) => {
    const serviceId = new ObjectId(req.params.id);

    const activeAppointment = await appointmentsCollection.findOne({
        serviceId,
        status: { $in: ['pending', 'confirmed'] }
    });

    if (activeAppointment) {
        throw new ApiError(
            409,
            'This service has pending or confirmed appointments. Deactivate it instead of deleting.'
        );
    }

    const result = await servicesCollection.deleteOne({ _id: serviceId });

    if (result.deletedCount === 0) throw new ApiError(404, 'Service not found');

    sendSuccess(res, null, 'Service deleted successfully');
});

/* ============================== APPOINTMENTS ============================== */

// GET /appointments/time-slots (public) -> predefined slot list
router.get('/appointments/time-slots', (req, res) => {
    sendSuccess(res, TIME_SLOTS, 'Time slots fetched successfully');
});

// GET /appointments/availability?date=YYYY-MM-DD (authenticated) -> which slots are booked
router.get('/appointments/availability', verifyToken, requireActiveUser, async (req, res) => {
    const date = asString(req.query.date);

    if (!isValidBookingDate(date)) throw new ApiError(400, 'Invalid date. Use YYYY-MM-DD');

    const booked = await appointmentsCollection
        .find({ appointmentDate: date, status: { $in: ['pending', 'confirmed'] } })
        .project({ timeSlot: 1, _id: 0 })
        .toArray();

    const bookedSlots = booked.map((a) => a.timeSlot);

    sendSuccess(
        res,
        {
            date,
            bookedSlots,
            availableSlots: TIME_SLOTS.filter((slot) => !bookedSlots.includes(slot))
        },
        'Availability fetched successfully'
    );
});

// POST /appointments (customer)
router.post('/appointments', writeLimiter, verifyToken, requireCustomer, async (req, res) => {
    const serviceId = asString(req.body.serviceId);
    const appointmentDate = asString(req.body.appointmentDate);
    const timeSlot = asString(req.body.timeSlot);
    const message = asString(req.body.message);

    const errors = {};
    if (!isValidObjectId(serviceId)) errors.serviceId = 'Invalid service ID';
    if (!isValidBookingDate(appointmentDate)) errors.appointmentDate = 'Invalid date. Use YYYY-MM-DD';
    if (!TIME_SLOTS.includes(timeSlot)) errors.timeSlot = 'Invalid time slot';
    if (message.length > 500) errors.message = 'Message must be 500 characters or less';

    if (Object.keys(errors).length > 0) {
        throw new ApiError(400, 'Validation failed', errors);
    }

    // No appointments in the past
    if (getBookingDateTime(appointmentDate, timeSlot) <= new Date()) {
        throw new ApiError(400, 'You cannot book an appointment in the past');
    }

    // Price / name / duration ALWAYS come from the database, never from the frontend
    const service = await servicesCollection.findOne({ _id: new ObjectId(serviceId) });

    if (!service) throw new ApiError(404, 'Service not found');
    if (service.status !== 'active') throw new ApiError(400, 'This service is currently not available for booking');

    const slotKey = `${appointmentDate}_${timeSlot}`;

    // Friendly pre-check (the unique index below is the real protection)
    const existing = await appointmentsCollection.findOne({ slotKey });
    if (existing) throw new ApiError(409, 'This time slot is already booked. Please choose another one.');

    const now = new Date();

    const appointment = {
        serviceId: service._id,
        customerId: req.user._id,
        customerName: req.user.name,
        customerEmail: req.user.email,
        customerPhone: req.user.phone || '',
        serviceSnapshot: {
            serviceName: service.serviceName,
            category: service.category,
            image: service.image,
            price: service.price,
            duration: service.duration
        },
        servicePrice: service.price,
        appointmentDate,
        timeSlot,
        message,
        status: 'pending',
        paymentStatus: 'unpaid',
        slotKey,
        createdAt: now,
        updatedAt: now
    };

    try {
        const result = await appointmentsCollection.insertOne(appointment);
        const created = await appointmentsCollection.findOne({ _id: result.insertedId });
        sendSuccess(res, created, 'Appointment request submitted successfully', 201);
    } catch (err) {
        // Two people booked the same slot at the same moment -> unique index rejects the second one
        if (err.code === 11000) {
            throw new ApiError(409, 'This time slot was just booked by someone else. Please choose another one.');
        }
        throw err;
    }
});

// GET /appointments/my-appointments (customer)
router.get('/appointments/my-appointments', verifyToken, requireCustomer, async (req, res) => {
    const { page, limit, skip } = getPagination(req.query, 10, 100);
    const filter = { customerId: req.user._id };

    if (['pending', 'confirmed', 'cancelled'].includes(req.query.status)) filter.status = req.query.status;

    const [appointments, total] = await Promise.all([
        appointmentsCollection.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
        appointmentsCollection.countDocuments(filter)
    ]);

    sendSuccess(res, appointments, 'Appointments fetched successfully', 200, {
        pagination: pageMeta(total, page, limit)
    });
});

// GET /appointments (admin)
router.get('/appointments', verifyToken, requireAdmin, async (req, res) => {
    const { page, limit, skip } = getPagination(req.query, 10, 100);
    const filter = {};

    if (['pending', 'confirmed', 'cancelled'].includes(req.query.status)) filter.status = req.query.status;
    if (['unpaid', 'paid'].includes(req.query.paymentStatus)) filter.paymentStatus = req.query.paymentStatus;
    if (isValidBookingDate(asString(req.query.date))) filter.appointmentDate = asString(req.query.date);

    const search = asString(req.query.search);
    if (search) {
        const regex = new RegExp(escapeRegex(search), 'i');
        filter.$or = [
            { customerName: regex },
            { customerEmail: regex },
            { 'serviceSnapshot.serviceName': regex }
        ];
    }

    const [appointments, total] = await Promise.all([
        appointmentsCollection.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
        appointmentsCollection.countDocuments(filter)
    ]);

    sendSuccess(res, appointments, 'Appointments fetched successfully', 200, {
        pagination: pageMeta(total, page, limit)
    });
});

// GET /appointments/:id (customer own / admin any)
router.get('/appointments/:id', verifyToken, requireActiveUser, validateObjectId('id'), async (req, res) => {
    const filter = { _id: new ObjectId(req.params.id) };

    // Customers can only see their own appointments
    if (req.user.role !== 'admin') filter.customerId = req.user._id;

    const appointment = await appointmentsCollection.findOne(filter);

    if (!appointment) throw new ApiError(404, 'Appointment not found');

    sendSuccess(res, appointment, 'Appointment fetched successfully');
});

// PATCH /appointments/:id/confirm (admin)
router.patch('/appointments/:id/confirm', verifyToken, requireAdmin, validateObjectId('id'), async (req, res) => {
    const id = new ObjectId(req.params.id);
    const now = new Date();

    const updated = await appointmentsCollection.findOneAndUpdate(
        { _id: id, status: 'pending' },
        { $set: { status: 'confirmed', confirmedAt: now, updatedAt: now } },
        { returnDocument: 'after' }
    );

    if (!updated) {
        const existing = await appointmentsCollection.findOne({ _id: id });
        if (!existing) throw new ApiError(404, 'Appointment not found');
        throw new ApiError(409, `Only pending appointments can be confirmed. This appointment is already ${existing.status}.`);
    }

    sendSuccess(res, updated, 'Appointment confirmed successfully');
});

// PATCH /appointments/:id/cancel (customer: own pending | admin: pending or confirmed)
router.patch('/appointments/:id/cancel', verifyToken, requireActiveUser, validateObjectId('id'), async (req, res) => {
    const id = new ObjectId(req.params.id);
    const isAdmin = req.user.role === 'admin';
    const now = new Date();

    if (isAdmin) {
        const current = await appointmentsCollection.findOne({ _id: id });
        if (!current) throw new ApiError(404, 'Appointment not found');
        if (current.checkoutLockToken) {
            throw new ApiError(409, 'Checkout is being prepared. Please try cancelling again shortly.');
        }
        if (current.status === 'confirmed' && current.checkoutSessionId) {
            await expireCheckoutForCancellation(current);
        }
    }

    // Paid appointments cannot be cancelled here: the money must be refunded in Stripe first.
    // Exclude an appointment being checked out to avoid racing session creation.
    const filter = isAdmin
        ? {
            _id: id,
            status: { $in: ['pending', 'confirmed'] },
            paymentStatus: { $ne: 'paid' },
            checkoutLockToken: { $exists: false }
        }
        : { _id: id, customerId: req.user._id, status: 'pending' };

    const updated = await appointmentsCollection.findOneAndUpdate(
        filter,
        {
            $set: {
                status: 'cancelled',
                cancelledAt: now,
                cancelledBy: isAdmin ? 'admin' : 'customer',
                updatedAt: now
            },
            $unset: { slotKey: '' } // frees the time slot
        },
        { returnDocument: 'after' }
    );

    if (!updated) {
        const ownershipFilter = isAdmin ? { _id: id } : { _id: id, customerId: req.user._id };
        const existing = await appointmentsCollection.findOne(ownershipFilter);

        if (!existing) throw new ApiError(404, 'Appointment not found');

        if (existing.paymentStatus === 'paid') {
            throw new ApiError(409, 'This appointment has already been paid. Refund the payment in Stripe before cancelling it.');
        }
        if (existing.checkoutLockToken) {
            throw new ApiError(409, 'Checkout is being prepared. Please try cancelling again shortly.');
        }

        throw new ApiError(
            409,
            isAdmin
                ? 'This appointment is already cancelled.'
                : `Only pending appointments can be cancelled. This appointment is already ${existing.status}.`
        );
    }

    sendSuccess(res, updated, 'Appointment cancelled successfully');
});

/* ================================ PAYMENTS ================================ */

function requireStripe() {
    if (!stripe) throw new ApiError(500, 'Payments are not configured on the server');
}

function sessionMatchesAppointment(session, appointment, { checkAmount = false } = {}) {
    const appointmentId = String(appointment._id);
    const customerId = String(appointment.customerId);
    if (
        session.mode !== 'payment' ||
        session.client_reference_id !== appointmentId ||
        session.metadata?.appointmentId !== appointmentId ||
        session.metadata?.customerId !== customerId
    ) return false;
    if (checkAmount && (!session.currency || session.currency.toLowerCase() !== PAYMENT_CURRENCY)) return false;
    if (!checkAmount && session.currency && session.currency.toLowerCase() !== PAYMENT_CURRENCY) return false;
    if (checkAmount && session.amount_total !== Math.round(Number(appointment.servicePrice) * 100)) return false;
    return true;
}

async function releaseCheckoutSession(appointment, session, status) {
    await transactionsCollection.updateOne(
        { stripeSessionId: session.id, status: { $ne: 'paid' } },
        {
            $set: { status },
            $setOnInsert: {
                appointmentId: appointment._id,
                customerId: appointment.customerId,
                amount: (session.amount_total ?? 0) / 100,
                currency: session.currency || PAYMENT_CURRENCY,
                createdAt: new Date()
            }
        },
        { upsert: true }
    );
    await appointmentsCollection.updateOne(
        { _id: appointment._id, checkoutSessionId: session.id },
        {
            $unset: {
                checkoutSessionId: '',
                checkoutSessionExpiresAt: '',
                checkoutAttemptId: '',
                checkoutLockToken: '',
                checkoutLockExpiresAt: ''
            },
            $set: { updatedAt: new Date() }
        }
    );
}

async function expireCheckoutForCancellation(appointment) {
    if (!stripe) throw new ApiError(503, 'Cannot safely cancel while payment processing is unavailable');

    let session;
    try {
        session = await stripe.checkout.sessions.retrieve(appointment.checkoutSessionId);
    } catch (error) {
        if (error.code !== 'resource_missing') throw error;
    }

    if (session && !sessionMatchesAppointment(session, appointment, { checkAmount: true })) {
        throw new ApiError(409, 'Stored Checkout Session does not match this appointment.');
    }
    if (session?.status === 'open') {
        session = await stripe.checkout.sessions.expire(session.id);
    }
    if (session?.status === 'complete') {
        throw new ApiError(409, 'Payment is completing. Refresh the appointment before cancelling it.');
    }
    if (session?.status === 'expired') {
        await releaseCheckoutSession(appointment, session, 'expired');
    } else if (!session) {
        await appointmentsCollection.updateOne(
            { _id: appointment._id, checkoutSessionId: appointment.checkoutSessionId },
            { $unset: { checkoutSessionId: '', checkoutSessionExpiresAt: '', checkoutAttemptId: '' } }
        );
    }
}

async function getReusableCheckout(appointment) {
    if (!appointment.checkoutSessionId) return null;
    let session;
    try {
        session = await stripe.checkout.sessions.retrieve(appointment.checkoutSessionId);
    } catch (error) {
        if (error.code !== 'resource_missing') throw error;
    }
    if (session && !sessionMatchesAppointment(session, appointment, { checkAmount: true })) {
        throw new ApiError(409, 'Stored Checkout Session does not match this appointment.');
    }
    if (session?.status === 'open' && session.url) return session;
    if (session?.status === 'expired') {
        await releaseCheckoutSession(appointment, session, 'expired');
        return null;
    }
    if (session?.status === 'complete') {
        throw new ApiError(409, 'Payment is processing. Please refresh the appointment status.');
    }
    if (!session) {
        await appointmentsCollection.updateOne(
            { _id: appointment._id, checkoutSessionId: appointment.checkoutSessionId },
            {
                $unset: {
                    checkoutSessionId: '',
                    checkoutSessionExpiresAt: '',
                    checkoutAttemptId: '',
                    checkoutLockToken: '',
                    checkoutLockExpiresAt: ''
                }
            }
        );
    }
    return null;
}

// MongoDB lease plus Stripe idempotency prevents concurrent duplicate Checkout Sessions.
router.post('/payments/checkout-session', writeLimiter, verifyToken, requireCustomer, async (req, res) => {
    requireStripe();
    const appointmentId = asString(req.body.appointmentId);
    if (!isValidObjectId(appointmentId)) throw new ApiError(400, 'Invalid appointment ID');

    let appointment = await appointmentsCollection.findOne({
        _id: new ObjectId(appointmentId),
        customerId: req.user._id
    });
    if (!appointment) throw new ApiError(404, 'Appointment not found');
    if (appointment.status !== 'confirmed') throw new ApiError(409, 'Only confirmed appointments can be paid');
    if (appointment.paymentStatus !== 'unpaid') throw new ApiError(409, 'This appointment is already paid');

    const existingSession = await getReusableCheckout(appointment);
    if (existingSession) return sendSuccess(res, { url: existingSession.url }, 'Checkout session reused');

    const lockToken = randomUUID();
    const now = new Date();
    const claimed = await appointmentsCollection.findOneAndUpdate(
        {
            _id: appointment._id,
            customerId: req.user._id,
            status: 'confirmed',
            paymentStatus: 'unpaid',
            $or: [
                { checkoutLockExpiresAt: { $exists: false } },
                { checkoutLockExpiresAt: { $lte: now } }
            ]
        },
        [{
            $set: {
                checkoutLockToken: lockToken,
                checkoutLockExpiresAt: new Date(now.getTime() + 120000),
                checkoutAttemptId: { $ifNull: ['$checkoutAttemptId', lockToken] }
            }
        }],
        { returnDocument: 'after' }
    );

    if (!claimed) {
        appointment = await appointmentsCollection.findOne({ _id: appointment._id });
        const session = appointment ? await getReusableCheckout(appointment) : null;
        if (session) return sendSuccess(res, { url: session.url }, 'Checkout session reused');
        throw new ApiError(409, 'Checkout is already being prepared. Please try again shortly.');
    }

    let session;
    try {
        session = await stripe.checkout.sessions.create(
            {
                mode: 'payment',
                customer_email: appointment.customerEmail,
                client_reference_id: String(appointment._id),
                line_items: [{
                    quantity: 1,
                    price_data: {
                        currency: PAYMENT_CURRENCY,
                        unit_amount: Math.round(Number(appointment.servicePrice) * 100),
                        product_data: {
                            name: appointment.serviceSnapshot.serviceName,
                            description: 'Appointment on ' + appointment.appointmentDate + ' at ' + appointment.timeSlot
                        }
                    }
                }],
                metadata: {
                    appointmentId: String(appointment._id),
                    customerId: String(appointment.customerId)
                },
                success_url: process.env.CLIENT_URI + '/payment/success?session_id={CHECKOUT_SESSION_ID}',
                cancel_url: process.env.CLIENT_URI + '/payment/cancel'
            },
            { idempotencyKey: 'salonbook-checkout-' + String(appointment._id) + '-' + claimed.checkoutAttemptId }
        );
        await appointmentsCollection.updateOne(
            { _id: appointment._id, checkoutLockToken: lockToken },
            {
                $set: {
                    checkoutSessionId: session.id,
                    checkoutSessionExpiresAt: session.expires_at ? new Date(session.expires_at * 1000) : null,
                    updatedAt: new Date()
                },
                $unset: { checkoutLockToken: '', checkoutLockExpiresAt: '' }
            }
        );
    } catch (error) {
        await appointmentsCollection.updateOne(
            { _id: appointment._id, checkoutLockToken: lockToken },
            { $unset: { checkoutLockToken: '', checkoutLockExpiresAt: '' } }
        );
        throw error;
    }
    sendSuccess(res, { url: session.url }, 'Checkout session created');
});

// Only verified webhooks update payment state; conditional writes make retries idempotent.
async function recordPaidSession(session) {
    const appointmentId = session.metadata?.appointmentId;
    if (!isValidObjectId(appointmentId)) {
        console.error('Stripe webhook: missing or invalid appointmentId metadata');
        return;
    }
    const appointment = await appointmentsCollection.findOne({ _id: new ObjectId(appointmentId) });
    if (!appointment || !sessionMatchesAppointment(session, appointment, { checkAmount: true })) {
        console.error('Stripe webhook: session does not match its appointment');
        return;
    }
    if (session.payment_status !== 'paid') return;

    if (appointment.paymentStatus === 'paid' && appointment.paymentSessionId === session.id) {
        await transactionsCollection.updateOne(
            { stripeSessionId: session.id },
            {
                $set: {
                    status: 'paid',
                    amount: session.amount_total / 100,
                    currency: session.currency,
                    updatedAt: new Date()
                },
                $setOnInsert: {
                    appointmentId: appointment._id,
                    customerId: appointment.customerId,
                    createdAt: new Date()
                }
            },
            { upsert: true }
        );
        return;
    }
    if (appointment.status !== 'confirmed' || appointment.paymentStatus !== 'unpaid') {
        console.warn('Stripe webhook: appointment is no longer eligible for payment', appointmentId);
        return;
    }

    const update = await appointmentsCollection.updateOne(
        { _id: appointment._id, status: 'confirmed', paymentStatus: 'unpaid' },
        {
            $set: {
                paymentStatus: 'paid',
                paymentSessionId: session.id,
                paidAt: new Date(),
                updatedAt: new Date()
            },
            $unset: {
                checkoutSessionId: '',
                checkoutSessionExpiresAt: '',
                checkoutAttemptId: '',
                checkoutLockToken: '',
                checkoutLockExpiresAt: ''
            }
        }
    );
    if (update.modifiedCount !== 1) return;

    await transactionsCollection.updateOne(
        { stripeSessionId: session.id },
        {
            $set: {
                status: 'paid',
                amount: session.amount_total / 100,
                currency: session.currency,
                updatedAt: new Date()
            },
            $setOnInsert: {
                appointmentId: appointment._id,
                customerId: appointment.customerId,
                createdAt: new Date()
            }
        },
        { upsert: true }
    );
}

async function recordFailedSession(session, status = 'failed') {
    const appointmentId = session.metadata?.appointmentId;
    if (!isValidObjectId(appointmentId)) return;
    const appointment = await appointmentsCollection.findOne({ _id: new ObjectId(appointmentId) });
    if (!appointment || !sessionMatchesAppointment(session, appointment)) return;

    if (status === 'failed' && session.status === 'open') {
        await transactionsCollection.updateOne(
            { stripeSessionId: session.id, status: { $ne: 'paid' } },
            {
                $set: { status: 'failed', updatedAt: new Date() },
                $setOnInsert: {
                    appointmentId: appointment._id,
                    customerId: appointment.customerId,
                    amount: (session.amount_total ?? 0) / 100,
                    currency: session.currency || PAYMENT_CURRENCY,
                    createdAt: new Date()
                }
            },
            { upsert: true }
        );
        return;
    }

    try {
        await releaseCheckoutSession(appointment, session, status);
    } catch (error) {
        if (error.code !== 11000) throw error;
    }
}

// Signature verification uses the raw body middleware registered before express.json().
router.post('/webhooks/stripe', async (req, res) => {
    if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
        return res.status(500).json({ success: false, message: 'Stripe webhook is not configured', errors: null });
    }
    let event;
    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            req.headers['stripe-signature'],
            process.env.STRIPE_WEBHOOK_SECRET
        );
    } catch {
        console.error('Stripe webhook signature verification failed');
        return res.status(400).json({ success: false, message: 'Invalid webhook signature', errors: null });
    }

    switch (event.type) {
        case 'checkout.session.completed':
        case 'checkout.session.async_payment_succeeded': {
            const session = event.data.object;
            if (session.payment_status === 'paid') await recordPaidSession(session);
            break;
        }
        case 'checkout.session.async_payment_failed':
            await recordFailedSession(event.data.object, 'failed');
            break;
        case 'checkout.session.expired':
            await recordFailedSession(event.data.object, 'expired');
            break;
        default:
            break;
    }
    res.json({ received: true });
});

// GET /payments/status?session_id=cs_... (customer)
// Used by the Payment Success page. It only reports what the webhook already stored.
router.get('/payments/status', verifyToken, requireCustomer, async (req, res) => {
    const sessionId = asString(req.query.session_id);

    if (!/^cs_[A-Za-z0-9_]+$/.test(sessionId)) throw new ApiError(400, 'Invalid session ID');

    const transaction = await transactionsCollection.findOne({
        stripeSessionId: sessionId,
        customerId: req.user._id
    });

    sendSuccess(
        res,
        transaction
            ? { status: transaction.status, appointmentId: transaction.appointmentId }
            : { status: 'processing' },
        'Payment status fetched successfully'
    );
});

// GET /transactions (admin, READ-ONLY). There is no endpoint to create or edit payments:
// transactions are written only by the verified Stripe webhook.
router.get('/transactions', verifyToken, requireAdmin, async (req, res) => {
    const { page, limit, skip } = getPagination(req.query, 10, 100);
    const match = {};

    if (['paid', 'failed'].includes(req.query.status)) match.status = req.query.status;

    const [items, total] = await Promise.all([
        transactionsCollection
            .aggregate([
                { $match: match },
                { $sort: { createdAt: -1 } },
                { $skip: skip },
                { $limit: limit },
                {
                    $lookup: {
                        from: 'appointments',
                        localField: 'appointmentId',
                        foreignField: '_id',
                        as: 'appointment'
                    }
                },
                { $unwind: { path: '$appointment', preserveNullAndEmptyArrays: true } },
                {
                    $project: {
                        appointmentId: 1,
                        customerId: 1,
                        amount: 1,
                        currency: 1,
                        stripeSessionId: 1,
                        status: 1,
                        createdAt: 1,
                        customerName: '$appointment.customerName',
                        customerEmail: '$appointment.customerEmail',
                        serviceName: '$appointment.serviceSnapshot.serviceName',
                        appointmentDate: '$appointment.appointmentDate',
                        timeSlot: '$appointment.timeSlot'
                    }
                }
            ])
            .toArray(),
        transactionsCollection.countDocuments(match)
    ]);

    sendSuccess(res, items, 'Transactions fetched successfully', 200, {
        pagination: pageMeta(total, page, limit)
    });
});

/* ================================ DASHBOARD =============================== */

async function appointmentStatusCounts(match = {}) {
    const rows = await appointmentsCollection
        .aggregate([{ $match: match }, { $group: { _id: '$status', count: { $sum: 1 } } }])
        .toArray();

    const result = { total: 0, pending: 0, confirmed: 0, cancelled: 0 };

    for (const row of rows) {
        if (row._id in result) result[row._id] = row.count;
        result.total += row.count;
    }

    return result;
}

// GET /dashboard/customer-stats
router.get('/dashboard/customer-stats', verifyToken, requireCustomer, async (req, res) => {
    const counts = await appointmentStatusCounts({ customerId: req.user._id });

    sendSuccess(
        res,
        {
            totalAppointments: counts.total,
            pendingAppointments: counts.pending,
            confirmedAppointments: counts.confirmed,
            cancelledAppointments: counts.cancelled
        },
        'Customer statistics fetched successfully'
    );
});

// GET /dashboard/admin-stats
router.get('/dashboard/admin-stats', verifyToken, requireAdmin, async (req, res) => {
    const [counts, totalCustomers, totalServices, activeServices, successfulPayments] = await Promise.all([
        appointmentStatusCounts(),
        usersCollection.countDocuments({ role: { $ne: 'admin' } }),
        servicesCollection.countDocuments(),
        servicesCollection.countDocuments({ status: 'active' }),
        transactionsCollection.countDocuments({ status: 'paid' })
    ]);

    sendSuccess(
        res,
        {
            totalCustomers,
            totalServices,
            activeServices,
            inactiveServices: totalServices - activeServices,
            totalAppointments: counts.total,
            pendingAppointments: counts.pending,
            confirmedAppointments: counts.confirmed,
            cancelledAppointments: counts.cancelled,
            totalSuccessfulPayments: successfulPayments
        },
        'Admin statistics fetched successfully'
    );
});

// GET /dashboard/recent-appointments
router.get('/dashboard/recent-appointments', verifyToken, requireAdmin, async (req, res) => {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 5, 1), 20);

    const appointments = await appointmentsCollection
        .find({})
        .sort({ createdAt: -1 })
        .limit(limit)
        .project({
            customerName: 1,
            'serviceSnapshot.serviceName': 1,
            appointmentDate: 1,
            timeSlot: 1,
            status: 1,
            paymentStatus: 1,
            createdAt: 1
        })
        .toArray();

    sendSuccess(res, appointments, 'Recent appointments fetched successfully');
});

/* ============================== IMAGE UPLOAD ============================== */

const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024, files: 1 },
    fileFilter: (req, file, cb) => {
        if (!ALLOWED_IMAGE_TYPES.includes(file.mimetype)) {
            return cb(new ApiError(400, 'Only JPG, PNG, WEBP or GIF images are allowed'));
        }
        cb(null, true);
    }
});

// POST /upload/image  (multipart/form-data, field name: "image")
router.post(
    '/upload/image',
    writeLimiter,
    verifyToken,
    requireActiveUser,
    upload.single('image'),
    async (req, res) => {
        if (!req.file) throw new ApiError(400, 'Please attach an image file (field name: image)');

        if (!process.env.IMGBB_API_KEY) {
            throw new ApiError(500, 'Image upload is not configured on the server');
        }

        const form = new FormData();
        form.append('image', req.file.buffer.toString('base64'));

        let response;
        let json;

        try {
            response = await fetch(
                `https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`,
                { method: 'POST', body: form }
            );
            json = await response.json();
        } catch (err) {
            console.error('ImgBB request failed');
            throw new ApiError(502, 'Image upload failed. Please try again.');
        }

        if (!response.ok || !json?.success) {
            console.error('ImgBB upload rejected, status:', response.status);
            throw new ApiError(502, 'Image upload failed. Please try again.');
        }

        sendSuccess(
            res,
            { url: json.data.display_url || json.data.url },
            'Image uploaded successfully',
            201
        );
    }
);
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
