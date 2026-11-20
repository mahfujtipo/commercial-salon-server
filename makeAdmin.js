import { MongoClient } from 'mongodb';
import 'dotenv/config';

// Usage: npm run make-admin -- admin@example.com
// Register the account through the normal Sign Up page first, then run this once.

const email = process.argv[2]?.toLowerCase();

if (!email) {
    console.error('Usage: node makeAdmin.js <email>');
    process.exit(1);
}

if (!process.env.MONGODB_URI) {
    console.error('MONGODB_URI is missing from environment variables');
    process.exit(1);
}

const client = new MongoClient(process.env.MONGODB_URI);

try {
    await client.connect();

    const result = await client
        .db('salon-database')
        .collection(process.env.USER_COLLECTION || 'user')
        .updateOne({ email }, { $set: { role: 'admin', isBlocked: false, updatedAt: new Date() } });

    console.log(result.matchedCount ? `Admin role assigned to ${email}` : `No user found with email ${email}`);
} finally {
    await client.close();
}
