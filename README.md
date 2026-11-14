# FridMan HTTPS bridge — temporary Render test

Upload server.py, requirements.txt, README.md and .gitignore to repository root. No APK or game script is needed on this server.

Render Web Service settings:
- Runtime: Python 3
- Branch: main
- Root directory: empty
- Build: pip install -r requirements.txt
- Start: python server.py
- Instance: Free ($0)
- Health check: /health
- Environment: OPERATOR_TOKEN and PAIR_CODE, DIFFERENT random ASCII strings, minimum 32 characters each. Use Render Generate for each separately. Never commit these to GitHub.

After deployment open https://YOUR-SERVICE.onrender.com/health. Expected JSON: service FridMan relay, version 1.
On phone: URL without /health, local script autoslot, PAIR_CODE as pairing code. Leave JS commands disabled initially.

IMPORTANT: This is a test relay, not production hardened. Render free filesystem and RAM are temporary. Restart/sleep loses session, queue and results. Configured PAIR_CODE becomes usable again on process restart: change it in Render before a new test and do not treat it as permanently spent. Pair code expires one hour after process startup. Session lasts at most one hour after pairing. No automatic command retry. Stop on phone and revoke server-side after testing. Stop cannot undo executed code.

API (Authorization: Bearer OPERATOR_TOKEN):
GET /v1/operator/status
POST /v1/operator/job JSON {"session":"actual-session-from-status","op":"status","ttl":60}
POST /v1/operator/revoke JSON {}
Revoke invalidates device and pending jobs; fresh random code is deliberately not exposed publicly. To pair again, change PAIR_CODE in Render and restart/deploy.

Device endpoints and job protocol are compatible with the supplied APK. No public control panel. Public / and /health contain no secrets. Script/log reads and staged edits require operator auth and a paired, consenting device. JS commands additionally require the phone's explicit command permission. Staged scripts require local approval. Do not enable commands until read-only testing succeeds.

This package serializes relay authentication/operations with a lock to avoid auth/revoke races in this process. Android-side deduplication and full PID/revision permit caveats are NOT fixed by deploying this server. Do not use for unattended commands.
