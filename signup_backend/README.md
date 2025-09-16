# Signup Backend

FastAPI backend providing APIs for:
- User registration and login with JWT
- Onboarding progress tracking for multi-step signup
- Placeholder endpoints for Google/Apple social sign-ins

## Run

Install dependencies (CI will handle in pipelines):
- See requirements.txt

Start server:
- uvicorn src.api.main:app --host 0.0.0.0 --port 3001 --reload

Regenerate OpenAPI spec:
- python -m src.api.generate_openapi

## Environment Variables (set in .env by orchestrator)
- MONGODB_URL
- MONGODB_DB
- JWT_SECRET_KEY
- JWT_ALGORITHM (default HS256)
- JWT_ACCESS_TOKEN_EXPIRE_MINUTES (default 60)
- CORS_ALLOW_ORIGINS (comma-separated, default "*")

Note: Do not commit .env. Provide values through environment.

## API Summary

- GET /              Health
- POST /auth/register  Register user (email/password)
- POST /auth/login     Login, returns access token
- GET /auth/me         Get current user (Bearer token)
- POST /auth/social    Placeholder social sign-in (Google/Apple)
- GET /onboarding/progress   Get onboarding map
- POST /onboarding/step      Update a step (status/data)

Refer to /docs for interactive OpenAPI documentation.
