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
