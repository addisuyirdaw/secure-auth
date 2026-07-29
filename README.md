# 🔐 Secure Auth — Enterprise Identity & Security System

A production-grade **authentication and authorization system** built with Node.js, TypeScript, and Express. Features real-time threat detection, Google OAuth, JWT rotation, and a beautiful security control center dashboard.

![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=flat-square&logo=node.js&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?style=flat-square&logo=typescript&logoColor=white)
![Express](https://img.shields.io/badge/Express-4.x-000000?style=flat-square&logo=express&logoColor=white)
![Prisma](https://img.shields.io/badge/Prisma-ORM-2D3748?style=flat-square&logo=prisma&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-Auth-000000?style=flat-square&logo=jsonwebtokens&logoColor=white)
![Google OAuth](https://img.shields.io/badge/Google-OAuth2-4285F4?style=flat-square&logo=google&logoColor=white)

---

## ✨ Features

### 🛡️ Security Engine
- **Brute-force protection** — IP-based rate limiting with automatic lockout and Redis/in-memory fallback
- **Impossible Travel Detection** — flags logins from geographically implausible locations within a short time window
- **Token Hijacking Protection** — detects refresh token reuse after rotation (compromise detection)
- **Risk Scoring Engine** — assigns a risk score to every login event based on device fingerprint, IP, location, and behavior

### 🔑 Authentication
- **JWT Access + Refresh Token** rotation with short-lived access tokens (15 min)
- **Google OAuth 2.0** — one-click sign-in with full session management
- **bcrypt** password hashing (configurable rounds)
- **Session management** — view, revoke individual or all active sessions

### 📊 Security Control Center (Dashboard)
- Live **Active Sessions** viewer
- **Security Event Logs** with real-time threat classification
- **Simulation Console** — pen-test your own system:
  - Brute-Force Attack Simulation
  - Impossible Travel Detection
  - Token Reuse / Hijacking Protection
- **Mock Email Sandbox** — view verification and alert emails without an SMTP server

### 📧 Email Notifications
- Account verification on registration
- Security alerts for suspicious login attempts
- Password reset flow

---

## 🏗️ Architecture

```
secure-auth/
├── src/
│   ├── index.ts              # App entry point
│   ├── routes/
│   │   └── auth.routes.ts    # All auth endpoints
│   ├── services/
│   │   ├── auth.service.ts       # Core auth logic
│   │   ├── session.service.ts    # Session CRUD
│   │   ├── token.service.ts      # JWT issue/verify/rotate
│   │   ├── risk.service.ts       # Risk scoring engine
│   │   └── email.service.ts      # Email notifications
│   ├── middleware/
│   │   ├── rateLimiter.ts        # Brute-force protection
│   │   └── authenticate.ts       # JWT guard middleware
│   ├── utils/
│   │   └── asyncHandler.ts       # Express async error wrapper
│   └── config/
│       └── passport.ts           # Google OAuth strategy
├── prisma/
│   └── schema.prisma         # Database schema (SQLite/Postgres)
├── public/
│   ├── index.html            # Security Control Center UI
│   └── style.css
└── .env.example
```

---

## 🚀 Getting Started

### Prerequisites
- Node.js 18+
- npm or yarn

### 1. Clone & Install

```bash
git clone https://github.com/mikiyas1295/secure-auth.git
cd secure-auth
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your values:

```env
NODE_ENV=development
PORT=3000
DATABASE_URL="file:./dev.db"

# JWT
JWT_ACCESS_SECRET=your_super_secret_key_at_least_32_chars
JWT_ACCESS_EXPIRY=15m
REFRESH_TOKEN_EXPIRY_DAYS=30

# Google OAuth (from Google Cloud Console)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

# SMTP (optional — mock sandbox works without it)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-smtp-user
SMTP_PASS=your-smtp-pass

BCRYPT_ROUNDS=12
```

### 3. Set Up Database

```bash
npx prisma migrate dev --name init
```

### 4. Run the Server

```bash
npx ts-node src/index.ts
```

Open **http://localhost:3000** to access the Security Control Center.

---

## 🔌 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/register` | Register a new user |
| `POST` | `/auth/login` | Login with email + password |
| `POST` | `/auth/refresh` | Rotate access token using refresh token |
| `POST` | `/auth/logout` | Revoke current session |
| `GET` | `/auth/google` | Initiate Google OAuth flow |
| `GET` | `/auth/google/callback` | Google OAuth callback |
| `GET` | `/auth/sessions` | List all active sessions (auth required) |
| `DELETE` | `/auth/sessions/:id` | Revoke a specific session |
| `DELETE` | `/auth/sessions` | Revoke all sessions |
| `GET` | `/auth/security-events` | Fetch security event log |
| `POST` | `/auth/verify-email` | Verify email with token |
| `POST` | `/auth/forgot-password` | Request password reset |
| `POST` | `/auth/reset-password` | Complete password reset |

---

## 🧪 Security Simulations

The **Simulation Console** at `/` lets you trigger real attack scenarios:

| Simulation | What It Tests |
|---|---|
| **Brute-Force Attack** | 5 rapid failed logins → lockout triggers |
| **Impossible Travel** | Login from Tokyo → London in seconds → blocked |
| **Token Hijacking** | Reuse a rotated refresh token → all sessions revoked |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js 18+ |
| Language | TypeScript |
| Framework | Express 4 |
| ORM | Prisma |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Auth | JWT + Passport.js |
| OAuth | Google OAuth 2.0 |
| Rate Limiting | express-rate-limit + Redis (with in-memory fallback) |
| Password Hashing | bcryptjs |
| Email | Nodemailer |

---

## 📄 License

MIT — free to use and adapt.

---

> Built as a portfolio demonstration of enterprise-grade authentication patterns, security threat detection, and full-stack TypeScript development.
