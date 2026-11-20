# SalonBook - Server (REST API)

Backend for **SalonBook**, a salon appointment booking platform. Customers browse salon services and request
appointments; the admin manages services, appointments and customers.

> Stripe payments are planned for a later phase. Appointments already carry `paymentStatus: "unpaid"` so the
> webhook flow can be added without changing the schema.

## Important Features

- JWT verification (Better Auth JWKS via `jose`) with the **current role and blocked status read from MongoDB**
- Role-based access control (`admin` / `customer`) on every protected route
- Services: CRUD, activate/deactivate, search by name, category filter, price range, sort by price, pagination
- Appointments: booking, availability, customer cancel (own, pending), admin confirm / cancel
- **Double-booking protection** with a sparse unique MongoDB index (safe for simultaneous requests)
- Service snapshot stored in every appointment (price/name stay consistent if the service changes later)
- Admin user management (list, details, block, unblock)
- Dashboard statistics for customer and admin
- ImgBB image upload through the server (API key never reaches the client)
- Helmet, CORS, rate limiting, input validation, centralized error handling

## Technology Stack

Node.js, Express 5, MongoDB (native driver), jose (JWT/JWKS), Helmet, express-rate-limit, Multer, dotenv, CORS.

## Installation

```bash
git clone <server-repo-link>
cd salon-server
npm install
cp .env.example .env   # then fill in the values
```

## How to Run Locally

```bash
npm run dev     # nodemon
npm start       # production mode
```

The API runs on `http://localhost:8000` and all routes live under `/api/v1`.

## Required Environment Variables (names only)

| Name | Purpose |
|---|---|
| `PORT` | Server port |
| `NODE_ENV` | `development` or `production` |
| `MONGODB_URI` | MongoDB connection string (database: `salon-database`) |
| `CLIENT_URI` | Next.js client URL (CORS) |
| `BETTER_AUTH_URL` | Better Auth base URL (JWKS discovery) |
| `IMGBB_API_KEY` | ImgBB API key |
| `JWT_ISSUER`, `JWT_AUDIENCE` | Optional JWT claim checks |
| `USER_COLLECTION` | Optional, Better Auth user collection name (default `user`) |

Never commit `.env`.

## Authentication and Authorization

1. The Next.js app uses Better Auth with the JWT plugin and sends `Authorization: Bearer <token>`.
2. `verifyToken` verifies the signature against `{BETTER_AUTH_URL}/api/auth/jwks`, checks expiry
   (and issuer/audience if configured), then loads the user from MongoDB by email.
3. Role and `isBlocked` always come from the database, never from the token or the frontend.
4. `requireAdmin`, `requireCustomer` and `requireActiveUser` enforce access. Blocked users receive `403`.

### Creating the admin

Admin accounts are never created through public signup. Register normally, then run:

```bash
npm run make-admin -- admin@example.com
```

## Database Collections

`user` (managed by Better Auth, extended with `role`, `isBlocked`, `phone`), `services`, `appointments`.

## API Endpoints (prefix `/api/v1`)

| Method | Endpoint | Access |
|---|---|---|
| GET / PATCH | `/users/me` | Authenticated |
| GET | `/users`, `/users/:id` | Admin |
| PATCH | `/users/:id/block`, `/users/:id/unblock` | Admin |
| GET | `/services` (`search, category, minPrice, maxPrice, sort=price_asc\|price_desc, page, limit`) | Public |
| GET | `/services/featured`, `/services/categories`, `/services/:id` | Public |
| GET | `/services/admin/all`, `/services/admin/:id` | Admin |
| POST / PATCH / DELETE | `/services`, `/services/:id` | Admin |
| PATCH | `/services/:id/status` | Admin |
| GET | `/appointments/time-slots` | Public |
| GET | `/appointments/availability?date=YYYY-MM-DD` | Authenticated |
| POST | `/appointments` | Customer |
| GET | `/appointments/my-appointments` | Customer |
| GET | `/appointments` | Admin |
| GET | `/appointments/:id` | Owner / Admin |
| PATCH | `/appointments/:id/confirm` | Admin |
| PATCH | `/appointments/:id/cancel` | Customer (own pending) / Admin |
| GET | `/dashboard/customer-stats` | Customer |
| GET | `/dashboard/admin-stats`, `/dashboard/recent-appointments` | Admin |
| POST | `/upload/image` (multipart, field `image`) | Authenticated |

Responses use `{ success, message, data }` (plus `pagination` for lists). Errors use `{ success: false, message, errors }`.

## Deployment (Vercel)

`vercel.json` is included. Add all environment variables in the Vercel project settings, set
`CLIENT_URI` to the live client URL, and deploy.

## Links

- Live Website: _add link_
- Client Repository: _add link_
- Server Repository: _add link_
