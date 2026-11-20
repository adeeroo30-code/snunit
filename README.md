# Snunit checklist trainer

Unofficial study app made by a trainee for personal practice: flashcards, recite mode, mixed and
regular tests, map lessons, a 3D cockpit sim, a work-in-progress 3D transitions sim, and optional accounts
with shared "hardest checklist" stats and a top-10 leaderboard.

**Not an official product.** Not made, endorsed or approved by the Israeli Air Force or the IDF.
The official checklist booklet and your instructor always take precedence over this app.
The checklist content belongs to its owners; this repository grants no rights to it. If you are a
rights holder and want something removed, open an issue and it will be taken down.

- `index.html` – the whole app (single file).
- `schema.sql` – database setup for accounts (Supabase SQL editor); `security.sql` – login lockout,
  sign-up throttle and account deletion (already included at the end of `schema.sql`); `board.sql` – leaderboard
  (points can only grow at human speed: 1 per second, 1,200 per day); `reset.sql` – restart for the June 2025 booklet
  (backs up and clears progress and stats; accounts stay).

Accounts store only a username, a bcrypt password hash, study progress and per-checklist mistake
counts. The username and points appear on the leaderboard unless the user hides them. No email, phone, location, ads or tracking. Users can delete their account from the app.
