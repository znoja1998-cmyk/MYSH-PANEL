# MYSH PANEL — starter backend

This is the first real backend foundation, not a hosted/live service yet.

## Included
- Owner bootstrap from environment variables (no default password)
- Username/password login with bcrypt and short-lived JWT
- Roles: owner, admin, seller, member
- Per-seller permissions: create_keys, view_keys, suspend_keys, manage_customers, view_sales
- Key types:
  - MEMBER: `MYSH-M-1H|3H|6H|12H|1D|3D|7D|14D|30D|60D-XXXX-XXXX`
  - TEST: `MYSH-TEST-XXXX-XXXX`
  - ADMIN: `MYSH-ADMIN-XXXX-XXXX`
- First-use activation binds a key to one HWID; only a SHA-256 hash is stored
- MEMBER duration starts at first activation; TEST and ADMIN have no automatic expiry
- Suspend/revoke endpoints and audit log
- SQLite database and basic rate limiting/security headers

## Run locally
1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env`.
3. Set a unique `JWT_SECRET` (32+ characters) and a strong `OWNER_PASSWORD` (12+ characters).
4. Run `npm install`, then `npm start`.
5. Check `http://localhost:3000/health`.

Never publish `.env`, passwords, JWT secrets, raw keys, or real HWIDs. Use HTTPS in production.

## Important next steps before production
- Responsive NEON DARK dashboard, key generator, key list, user creation, and per-seller permission editor are included in `public/index.html`.
- Add CSRF-safe browser session handling if using cookie auth, stronger request validation, pagination, and role-specific audit views.
- Add account suspension, a formal HWID reset approval workflow, key expiration sweeps, seller/customer management, and tests. A restricted admin HWID reset endpoint is currently included.
- Add automated tests, backups, monitoring, HTTPS, and production database hosting.
- Connect an external app only through its documented/authorized API. HAPP integration cannot be completed without its official API/deep-link documentation.
- Review deployment settings and threat model before real customer use.

This starter has not been deployed, penetration-tested, or connected to HAPP.
