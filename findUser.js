import { MongoClient } from 'mongodb';
import 'dotenv/config';

const email = (process.argv[2] || '').toLowerCase();
const client = new MongoClient(process.env.MONGODB_URI);
await client.connect();

const { databases } = await client.db().admin().listDatabases();

for (const d of databases) {
    if (['admin', 'local', 'config'].includes(d.name)) continue;
    const cols = await client.db(d.name).listCollections().toArray();
    for (const c of cols) {
        const found = await client
            .db(d.name)
            .collection(c.name)
            .findOne({ email: new RegExp(`^${email}$`, 'i') });
        if (found) console.log(`FOUND in database "${d.name}", collection "${c.name}"`, { role: found.role, isBlocked: found.isBlocked });
    }
}

await client.close();