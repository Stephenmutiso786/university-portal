# Tech Hub University Portal (Hosting Ready)

Modern full-stack university portal with role-based access and complete module coverage for academics, finance, administration, communication, LMS, analytics, security, and student life workflows.
University Hub Centre.

## What Is Production-Ready Here
- Frontend is served by backend (single deployable app)
- Environment-based configuration (`backend/.env`)
- Security headers, API rate limiting, request-size limits
- Configurable CORS and proxy-safe mode
- Health + readiness endpoints
- Graceful shutdown handling (PM2/Docker safe)
- Docker + Docker Compose deployment files
- PM2 deployment config for VPS hosting

## Tech Stack
- Backend: Node.js + Express (`backend/index.js`)
- Frontend: HTML/CSS/JavaScript (`frontend/index.html`)
- Storage: JSON persistence file (configurable via `DATA_FILE`)
- Database schema: Prisma + PostgreSQL (`backend/prisma/schema.prisma`)

## Quick Start (Local)
1. Install dependencies:
```bash
cd backend
npm install
```
2. Create env file:
```bash
cp .env.example .env
```
3. Run app:
```bash
npm start
```
4. Open `http://localhost:4000`

## Seed Login Accounts
- `stephemutiso19@gmail.com` / `2006@shawn_M`
- `lecturer@example.com` / `lecturerpass`
- `student@example.com` / `studentpass`

## Environment Variables
Use `backend/.env.example` as template.

Important keys:
- `NODE_ENV=production`
- `PORT=4000`
- `JWT_SECRET=<long-random-secret>`
- `TRUST_PROXY=true` (set when behind Nginx/Cloudflare/Render/etc.)
- `CORS_ORIGIN=https://portal.example.com`
- `DATA_FILE=/app/backend/data/store.json`
- `DATABASE_URL=postgresql://portal_user:portal_password@postgres:5432/university_portal?schema=public`
- `STORAGE_ENGINE=json`

## PostgreSQL + Prisma Setup
The project now includes a full production Prisma schema for users, academics, finance, communication, LMS, hostel, clearance, alumni, and audit logs.

Run Prisma setup:
```bash
cd backend
npm install
cp .env.example .env
# set DATABASE_URL in .env
npm run db:setup
```

Useful Prisma commands:
```bash
npm run prisma:generate
npm run prisma:push
npm run prisma:migrate
npm run prisma:studio
npm run seed
```

## Deploy Option A: Docker (Recommended)
1. Create env file:
```bash
cp backend/.env.example backend/.env
```
2. Set production values in `backend/.env`.
3. Start containers (the portal service will run Prisma migrations + seed on startup):
```bash
docker compose up -d --build
```
4. (Optional) If you need to re-run migrations/seed later:
```bash
docker compose run --rm portal sh -lc "cd /app/backend && npm run db:setup"
```
5. Check health:
```bash
curl http://localhost:4000/api/health
curl http://localhost:4000/api/ready
```

## Deploy Option B: VPS + PM2
1. Copy project to server (example path `/var/www/techhub-portal`).
2. Install Node 20+ and PM2:
```bash
npm i -g pm2
```
3. Configure env:
```bash
cd /var/www/techhub-portal/backend
cp .env.example .env
# edit .env for production
npm install --omit=dev
```
4. Start with PM2:
```bash
npm run pm2:start
pm2 save
pm2 startup
```

## Reverse Proxy (Nginx) Notes
- Proxy `https://portal.example.com` to `http://127.0.0.1:4000`
- Forward headers: `Host`, `X-Forwarded-For`, `X-Forwarded-Proto`
- Keep TLS termination at Nginx/Load Balancer
- Template config: `deploy/nginx-techhub.conf`

## Operational Checklist Before Going Live
- Change all default seed passwords
- Set strong `JWT_SECRET`
- Set exact `CORS_ORIGIN` domains
- Enable HTTPS at proxy/load balancer
- Configure regular backups for `DATA_FILE`
- Monitor logs and restart policy (PM2 or Docker)

## API Health Endpoints
- `GET /api/health`
- `GET /api/ready`

## Current Functional Modules
- Student: auth, add/drop, timetable, exam card, transcript, results, CGPA, assignments, attendance
- Lecturer: materials, assignments, marks, attendance, class list
- Finance: fee structures, balances, payments (`mpesa|bank|card`), statements
- Administration: admissions, departments, programs, semesters, courses, staff, reports, admin overview
- Communication: announcements, internal messages, notifications (email/SMS simulation)
- LMS: integrations + LMS overview (quizzes/discussion summary)
- Extras: hostels, library, clearance + admin review, alumni tracking, chatbot support
- Security: role-based access, 2FA enable endpoint, activity logs

## Next Production Upgrade (Recommended)
- Switch runtime data layer from JSON engine to Prisma engine across all API handlers (schema and seed are already in place).
- Prisma runtime migration status (done): auth (`/api/auth/*`), catalog (`/api/catalog/*`), student core (`/api/student/*`), lecturer core (`/api/lecturer/*`), finance (`/api/finance/*`), communications (`/api/communications/*`), LMS/calendar (`/api/lms/*`, `/api/academics/*`), extras (`/api/extras/*`), admin user management and reporting (`/api/admin/users*`, `/api/admin/reports/*`, `/api/admin/overview`).
