# SkillBridge — SIH 2026 Runtime Working Model

A self-contained full-stack prototype aligned with the SIH presentation: **Assess → Improve → Connect**.

## Run

Requirements: Node.js 18+.

```bash
npm start
```

Open **http://localhost:3000**.

No `npm install` is required. The runtime uses only Node.js built-in modules.

## Demo accounts

- Student: `aarav.demo@skillbridge.local` / `Student@123`
- Company: `nova.demo@skillbridge.local` / `Company@123`
- Admin: `admin.demo@skillbridge.local` / `Admin@123`

## Student flow

1. Register or log in.
2. Choose a target role.
3. Take the 8-question role-specific assessment (10-minute timer).
4. Submit all answers; timeout automatically submits answered questions and treats unanswered questions as incorrect.
5. Receive score, readiness stage, strengths, skill gaps and an explainable AI career plan.
6. Follow the personalized roadmap and mark tasks complete.
7. View skill-based internship matches and apply.

## Company flow

1. Register or log in.
2. Maintain company profile.
3. Post an internship and select required skills/levels.
4. Review candidates ranked by skill match.
5. Review applications and move candidates through shortlist/interview/selected/rejected states.

## Admin flow

The demo admin account provides a protected overview of students, companies, internships and applications.

## Assessment security

The assessment API never sends correct answers to the browser. The server validates the selected role, exact question set, answer indexes and required completion before scoring. Timeout submissions are explicitly supported.

## AI layer

The prototype uses an explainable, deterministic Skill Intelligence Engine so the complete assessment → skill-gap → roadmap flow works locally without an external API key. It is structured so a production LLM/ML provider can be added later without making the core demo dependent on that provider.

## Data

Demo data is stored in `backend/data/runtime.json`.

Reset to the clean demo state with:

```bash
npm run reset
```

## Verification

Run the automated backend/static smoke suite with:

```bash
npm test
```

The suite covers authentication, role authorization, all 8 assessment roles, question-answer leakage protection, full/partial/timeout submissions, AI reports, roadmap CRUD, profile updates, company internship creation, skill matching, applications, duplicate/capacity protection, company application status updates, candidate ranking, static assets and API error handling.


## Security hardening
- JWT_SECRET is required by the server (minimum 32 characters). The demo start scripts provide a local demo secret; use a unique environment secret for deployment.
- Passwords use scrypt; legacy SHA-256 demo hashes are upgraded automatically after successful login.
- Assessment attempts are server-issued with server-side expiry and cannot be replayed.
- Security headers are enabled and permissive CORS has been removed.
- Login attempts are rate-limited in memory.
- User/profile/internship input is validated and length-limited.

For a production deployment, replace the JSON store with PostgreSQL/MySQL and use HTTPS behind a reverse proxy.
