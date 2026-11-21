import { MongoClient } from 'mongodb';
import 'dotenv/config';

const email = (process.argv[2] || '').toLowerCase();
const client = new MongoClient(process.env.MONGODB_URI);
await client.connect();

const db = client.db(process.env.DB_NAME || 'SalonBook');
const users = db.collection(process.env.USER_COLLECTION || 'user');
const found = await users.findOne({ email });
if (found) console.log('FOUND in database', db.databaseName, 'collection', users.collectionName, { role: found.role, isBlocked: found.isBlocked });

await client.close();