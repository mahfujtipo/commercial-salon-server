# 💇 SalonBook – Server (REST API)

Backend server for **SalonBook**, a salon appointment booking platform where customers can explore salon services, book appointments, and manage their bookings. Administrators can manage services, appointments, customers, and platform activities through a secure dashboard.

Stripe payment integration is planned for a future phase. The appointment schema already includes `paymentStatus: "unpaid"` to support payment processing without requiring database schema changes.

---

## ✨ Key Features

- **JWT Authentication:** Secure token verification using Better Auth JWKS and `jose`.
- **Role-Based Access Control:** Separate permissions for `admin` and `customer`.
- **Database-Based Authorization:** User roles and blocked status are always verified against MongoDB.
- **Service Management:** Create, update, delete, activate, and deactivate salon services.
- **Advanced Service Filtering:** Search by name, filter by category and price range, sort, and paginate results.
- **Appointment Booking:** Customers can book appointments and manage their bookings.
- **Availability Management:** Check available appointment slots for specific dates.
- **Double-Booking Prevention:** Sparse unique MongoDB index prevents simultaneous bookings for the same slot.
- **Service Snapshots:** Appointment records preserve service names and prices at booking time.
- **Appointment Management:** Admins can confirm or cancel appointments, while customers can cancel their own pending bookings.
- **User Management:** Admins can view, block, and unblock customer accounts.
- **Dashboard Statistics:** Separate statistics for customers and administrators.
- **Image Upload:** Secure ImgBB image uploads handled through the backend.
- **Security:** Helmet, CORS, rate limiting, input validation, and centralized error handling.

---

## 🛠️ Technology Stack

| Technology         | Purpose                       |
| ------------------ | ----------------------------- |
| Node.js            | JavaScript runtime            |
| Express 5          | REST API framework            |
| MongoDB            | NoSQL database                |
| Better Auth        | Authentication provider       |
| jose               | JWT and JWKS verification     |
| Helmet             | HTTP security headers         |
| express-rate-limit | API rate limiting             |
| Multer             | File upload handling          |
| ImgBB              | Image hosting                 |
| dotenv             | Environment configuration     |
| CORS               | Cross-origin resource sharing |

---

## 📁 Project Installation

**1. Clone the repository**

```bash
git clone <server-repo-link>
```

**2. Navigate to the project directory**

```bash
cd salon-server
```

**3. Install dependencies**

```bash
npm install
```

**4. Configure environment variables**

```bash
cp .env.example .env
```

Add the required environment variable values to your `.env` file.

---

## 🚀 Running Locally

**Development mode**

```bash
npm run dev
```

**Production mode**

```bash
npm start
```

The server will run at:

```text
http://localhost:8000
```

All API endpoints are available under:

```text
/api/v1
```

---

## 🔐 Environment Variables

Configure the following variables in your `.env` file.

| Variable          | Description                                                 |
| ----------------- | ----------------------------------------------------------- |
| `PORT`            | Server port                                                 |
| `NODE_ENV`        | Application environment (`development` or `production`)     |
| `MONGODB_URI`     | MongoDB connection string                                   |
| `CLIENT_URI`      | Frontend URL for CORS configuration                         |
| `BETTER_AUTH_URL` | Better Auth base URL for JWKS discovery                     |
| `IMGBB_API_KEY`   | ImgBB API key for image uploads                             |
| `JWT_ISSUER`      | Optional JWT issuer validation                              |
| `JWT_AUDIENCE`    | Optional JWT audience validation                            |
| `USER_COLLECTION` | Optional Better Auth user collection name (default: `user`) |

**Important:** Never commit your `.env` file or expose API keys in the frontend.

---

## 🔑 Authentication & Authorization

SalonBook uses Better Auth with JWT-based authentication.

### Authentication Flow

1. The Next.js frontend authenticates users through Better Auth.
2. The frontend sends an access token with each protected request using the following header:

```http
Authorization: Bearer <token>
```

3. The `verifyToken` middleware verifies the JWT signature using the Better Auth JWKS endpoint:

```text
{BETTER_AUTH_URL}/api/auth/jwks
```

4. Token expiration and optional issuer/audience claims are validated.
5. The server retrieves the current user from MongoDB using their email.
6. User roles and blocked status are retrieved directly from the database.

### Authorization Middleware

| Middleware          | Purpose                                                  |
| ------------------- | -------------------------------------------------------- |
| `verifyToken`       | Verifies JWT authentication                              |
| `requireAdmin`      | Restricts access to administrators                       |
| `requireCustomer`   | Restricts access to customers                            |
| `requireActiveUser` | Prevents blocked users from accessing protected features |

Blocked users receive an HTTP `403 Forbidden` response.

### Creating an Admin Account

Admin accounts cannot be created through public registration.

First, register a normal account, then execute:

```bash
npm run make-admin -- admin@example.com
```

Replace `admin@example.com` with the registered user's email address.

---

## 🗄️ Database Collections

SalonBook uses MongoDB with the following collections:

| Collection     | Description                                                                          |
| -------------- | ------------------------------------------------------------------------------------ |
| `user`         | User accounts managed by Better Auth, extended with `role`, `isBlocked`, and `phone` |
| `services`     | Salon services, pricing, categories, and availability status                         |
| `appointments` | Customer bookings, appointment status, service snapshots, and payment status         |

### Appointment Payment Status

Appointments include:

```js
paymentStatus: "unpaid";
```

This allows Stripe payment integration to be added in a future development phase.

---

## 🌐 API Documentation

**Base URL**

```text
http://localhost:8000/api/v1
```

### 1. User Management

| Method | Endpoint             | Access        |
| ------ | -------------------- | ------------- |
| GET    | `/users/me`          | Authenticated |
| PATCH  | `/users/me`          | Authenticated |
| GET    | `/users`             | Admin         |
| GET    | `/users/:id`         | Admin         |
| PATCH  | `/users/:id/block`   | Admin         |
| PATCH  | `/users/:id/unblock` | Admin         |

### 2. Service Management

| Method | Endpoint               | Access |
| ------ | ---------------------- | ------ |
| GET    | `/services`            | Public |
| GET    | `/services/featured`   | Public |
| GET    | `/services/categories` | Public |
| GET    | `/services/:id`        | Public |
| GET    | `/services/admin/all`  | Admin  |
| GET    | `/services/admin/:id`  | Admin  |
| POST   | `/services`            | Admin  |
| PATCH  | `/services/:id`        | Admin  |
| DELETE | `/services/:id`        | Admin  |
| PATCH  | `/services/:id/status` | Admin  |

**Available Query Parameters**

The `GET /services` endpoint supports:

| Parameter  | Description                         |
| ---------- | ----------------------------------- |
| `search`   | Search services by name             |
| `category` | Filter by service category          |
| `minPrice` | Minimum service price               |
| `maxPrice` | Maximum service price               |
| `sort`     | Sort by `price_asc` or `price_desc` |
| `page`     | Current page number                 |
| `limit`    | Number of results per page          |

### 3. Appointment Management

| Method | Endpoint                                     | Access                         |
| ------ | -------------------------------------------- | ------------------------------ |
| GET    | `/appointments/time-slots`                   | Public                         |
| GET    | `/appointments/availability?date=YYYY-MM-DD` | Authenticated                  |
| POST   | `/appointments`                              | Customer                       |
| GET    | `/appointments/my-appointments`              | Customer                       |
| GET    | `/appointments`                              | Admin                          |
| GET    | `/appointments/:id`                          | Owner / Admin                  |
| PATCH  | `/appointments/:id/confirm`                  | Admin                          |
| PATCH  | `/appointments/:id/cancel`                   | Customer (own pending) / Admin |

### 4. Dashboard

| Method | Endpoint                         | Access   |
| ------ | -------------------------------- | -------- |
| GET    | `/dashboard/customer-stats`      | Customer |
| GET    | `/dashboard/admin-stats`         | Admin    |
| GET    | `/dashboard/recent-appointments` | Admin    |

### 5. Image Upload

| Method | Endpoint        | Access        |
| ------ | --------------- | ------------- |
| POST   | `/upload/image` | Authenticated |

**Request format:** `multipart/form-data`

**Field name:** `image`

The server uploads images to ImgBB, keeping the API key secure on the backend.

---

## 📦 API Response Format

Successful API responses follow this structure:

```json
{
  "success": true,
  "message": "Operation successful",
  "data": {}
}
```

List responses may additionally include pagination metadata.

Error responses follow this structure:

```json
{
  "success": false,
  "message": "Something went wrong",
  "errors": []
}
```

---

## 🛡️ Security Features

- JWT signature and expiration verification.
- Database-based role and account status validation.
- Role-based route protection.
- Protection against simultaneous appointment bookings.
- HTTP security headers using Helmet.
- CORS configuration.
- API rate limiting.
- Request input validation.
- Centralized error handling.
- Secure server-side image uploads.

---

## ☁️ Deployment (Vercel)

The project includes a `vercel.json` configuration for Vercel deployment.

**Deployment steps:**

1. Push the server code to GitHub.
2. Import the repository into Vercel.
3. Configure all required environment variables in Vercel Project Settings.
4. Set `CLIENT_URI` to your deployed Next.js frontend URL.
5. Verify the MongoDB connection and Better Auth configuration.
6. Deploy the project.

After deployment, your REST API will be accessible through your Vercel deployment URL.

---

## 🔗 Project Links

- **Live Website:** _Add live website URL_
- **Client Repository:** _Add frontend GitHub repository URL_
- **Server Repository:** _Add backend GitHub repository URL_

---

## 👨‍💻 Author

Developed as part of the **SalonBook** full-stack web application project.

---

<p align="center">
  <strong>SalonBook – Making salon appointments simple and convenient. 💇</strong>
</p>
