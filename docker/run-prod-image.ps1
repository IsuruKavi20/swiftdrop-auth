# Starts the production Docker image on THIS laptop, the way a server would (prod profile, settings from outside).
# Usage (PowerShell, from E:\EAD):   .\scripts\run-prod-image.ps1            then open http://localhost:9001
#                                     .\scripts\run-prod-image.ps1 -Tag 1.0.1 -Port 9002
# Needs: "docker compose up -d" (Postgres + Mailpit), .env, and .secrets\jwt-signing-key.pem (made by mvnw on first run).
# The URLs below are fake https test addresses: production requires https. Secrets are never put into the image.
param(
    [string]$Tag = "1.0.0",
    [int]$Port = 9001
)
$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
$key = Join-Path $project ".secrets\jwt-signing-key.pem"
$envFile = Join-Path $project ".env"

if (-not (Test-Path $key)) { throw "Signing key missing: $key (start the app once with .\mvnw spring-boot:run)" }
if (-not (Test-Path $envFile)) { throw ".env missing: copy .env.example to .env and fill it in" }

# Remove an old test container with the same name, if there is one
docker rm -f auth-local 2>$null | Out-Null

docker run -d --name auth-local -p "${Port}:9000" `
    --env-file $envFile `
    -e SPRING_PROFILES_ACTIVE=prod `
    -e DB_URL=jdbc:postgresql://host.docker.internal:5433/swiftdrop_auth `
    -e SWIFTDROP_JWT_ISSUER=https://auth.swiftdrop.test `
    -e SWIFTDROP_JWT_PRIVATE_KEY_LOCATION=/run/secrets/jwt-signing-key.pem `
    -e SWIFTDROP_PUBLIC_BASE_URL=https://auth.swiftdrop.test `
    -e SWIFTDROP_FRONTEND_BASE_URL=https://app.swiftdrop.test `
    -e SWIFTDROP_CORS_ALLOWED_ORIGINS=https://app.swiftdrop.test `
    -e "SWIFTDROP_TRUSTED_PROXIES=10\.\d{1,3}\.\d{1,3}\.\d{1,3}" `
    -e MAIL_HOST=host.docker.internal -e MAIL_PORT=1025 -e MAIL_USERNAME=test -e MAIL_PASSWORD=test `
    -v "${key}:/run/secrets/jwt-signing-key.pem:ro" `
    "swiftdrop-auth:$Tag"

Write-Host ""
Write-Host "Container 'auth-local' started from swiftdrop-auth:$Tag on http://localhost:$Port"
Write-Host "  watch it start : docker logs -f auth-local   (wait for 'Started AuthApplication', Ctrl+C stops watching)"
Write-Host "  test it        : curl.exe http://localhost:$Port/.well-known/jwks.json"
Write-Host "  remove it      : docker rm -f auth-local"
