# SalonBook Server

Express REST API for SalonBook, a salon appointment booking platform. It serves service catalog, appointment, dashboard, user administration, image upload, and Stripe payment operations.

## Technology

Node.js, Express 5, MongoDB native driver, Better Auth JWT/JWKS, jose, Stripe, ImgBB, Helmet, CORS, Multer, and express-rate-limit.

## Features

- Public active service listing, search, categories, price filtering/sorting, and pagination.
- Admin-only service management, appointment management, user blocking, and transaction history.
- Customer appointment booking, availability, ownership checks, and pending appointment cancellation.
- A MongoDB unique slot index prevents active duplicate bookings.
- Stripe Checkout uses database pricing, atomic checkout claims, reusable active sessions, and Stripe idempotency keys.
- Raw-body webhook signature verification validates appointment, customer, amount, currency, and payment state before recording payment.
- ImgBB image upload is proxied server-side so the API key stays private.

## Local setup

~~~powershell
npm install
Copy-Item .env.example .env
npm run dev
~~~

The API listens on http://localhost:8000 by default and uses the /api/v1 prefix. Register a customer first, then create an admin with npm run make-admin -- user@example.com.

## Environment variables

| Variable | Purpose |
|---|---|
| MONGODB_URI | MongoDB connection string |
| DB_NAME | Shared database name; set to SalonBook |
| USER_COLLECTION | Better Auth user collection; defaults to user |
| BETTER_AUTH_SECRET | Better Auth secret; configure the same value in the client |
| BETTER_AUTH_URL | Client Better Auth base URL for JWKS |
| BETTER_AUTH_ISSUER, BETTER_AUTH_AUDIENCE | Optional JWT claim validation |
| CLIENT_URI | Frontend origin for CORS and Stripe redirects |
| PORT, NODE_ENV | Server port and runtime environment |
| IMGBB_API_KEY | Private ImgBB key |
| STRIPE_SECRET_KEY | Private Stripe server key |
| STRIPE_WEBHOOK_SECRET | Stripe webhook signing secret |
| PAYMENT_CURRENCY | Checkout currency; defaults to usd |

Use placeholders in .env.example and put credentials only in ignored .env or deployment settings. Never commit .env.

## Authentication and authorization

The client obtains a Better Auth JWT and sends it as an Authorization: Bearer token. verifyToken validates it using the BETTER_AUTH_URL JWKS endpoint, then loads the user from MongoDB. Authorization middleware reads role and blocked status from that database, not from client input. Admin and customer operations use separate middleware.

## Database

Both client and server must use DB_NAME=SalonBook. Better Auth manages user, session, account, and verification records. The API manages services, appointments, and transactions. The server creates indexes for active booking slot uniqueness and Stripe session uniqueness. No migration or collection deletion is required.

## Stripe payment flow

The API accepts checkout only for the authenticated appointment owner when the appointment is confirmed and unpaid. It claims checkout creation atomically, reuses an open session, and releases expired/failed sessions for retry. The /api/v1/webhooks/stripe route receives the raw body and verifies the Stripe signature. The webhook records a transaction and marks an eligible appointment paid; the success page only reads status. Configure Stripe to send completed, asynchronous success/failure, and expired Checkout Session events to this endpoint.

## API and deployment

All REST endpoints use /api/v1. vercel.json configures the serverless entry point. Set production environment variables in the hosting provider and configure the live frontend origin and Stripe webhook URL.

## Links

- Live API: https://commercial-salon-server.vercel.app
- Client repository: https://github.com/mahfujtipo/commercial-salon-clientside
- Server repository: https://github.com/mahfujtipo/commercial-salon-server

## Core API routes

All paths below are relative to /api/v1.

| Feature | Routes |
|---|---|
| Users | GET/PATCH /users/me; admin GET /users and /users/:id; block/unblock user routes |
| Services | GET /services, /services/featured, /services/categories, /services/:id; admin CRUD and status routes |
| Appointments | GET /appointments/time-slots and /appointments/availability; customer POST /appointments and GET /appointments/my-appointments; admin appointment list, confirm, and cancellation |
| Payments | POST /payments/checkout-session; GET /payments/status; Stripe POST /webhooks/stripe; admin GET /transactions |
| Dashboards | GET /dashboard/customer-stats, /dashboard/admin-stats, /dashboard/recent-appointments |
| Images | Authenticated POST /upload/image |

## Production start

~~~powershell
npm start
~~~
