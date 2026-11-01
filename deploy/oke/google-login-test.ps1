# End-to-end Google login against the deployed service, playing the frontend's part (lesson 17).
#   powershell -ExecutionPolicy Bypass -File .\deploy\oke\google-login-test.ps1
# 1. Makes a browser secret (PKCE verifier) and sends only its SHA-256 fingerprint (challenge) to our service.
# 2. Opens the Google login. Afterwards the browser lands on the frontend address with #code=... in the URL.
# 3. Exchanges that one-time code (valid 60 s) plus the secret for tokens.
# Tokens are NOT printed: only a summary of the access token's claims.
param([string]$BaseUrl = 'https://auth.getswiftdrop.me')
$ErrorActionPreference = 'Stop'

function ConvertTo-Base64Url([byte[]]$bytes) {
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}
function ConvertFrom-Base64Url([string]$text) {
    $padded = $text.Replace('-', '+').Replace('_', '/')
    $padded += '=' * ((4 - $padded.Length % 4) % 4)
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($padded))
}

$secret = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($secret)
$verifier = ConvertTo-Base64Url $secret
$challenge = ConvertTo-Base64Url ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))

Write-Host "`nOpening Google login in your browser..." -ForegroundColor Cyan
Start-Process "$BaseUrl/oauth2/authorization/google?code_challenge=$challenge"
Write-Host 'Log in. Then the browser shows "can''t reach this page" at localhost:5173 - that is expected.'
Write-Host 'Copy the WHOLE address from the address bar (it contains #code=...).'
$pasted = Read-Host "`nPaste the address here, then press Enter (within 60 seconds)"

$pasted = $pasted.Trim()
if ($pasted -match 'error=') { throw "The service reported a failed Google login: $pasted" }
# Accept the whole address (…#code=XYZ) or just the code itself
if ($pasted -match 'code=([A-Za-z0-9_-]+)') {
    $code = $Matches[1]
} elseif ($pasted -match '^[A-Za-z0-9_-]{20,64}$') {
    $code = $pasted
} else {
    throw 'No code found in what you pasted.'
}

$body = Join-Path $env:TEMP 'swiftdrop-exchange.json'
try {
    @{ code = $code; verifier = $verifier } | ConvertTo-Json | Set-Content -Encoding ascii $body
    $response = curl.exe -s -H 'Content-Type: application/json' --data-binary "@$body" "$BaseUrl/api/v1/auth/google/exchange"
} finally {
    Remove-Item $body -ErrorAction SilentlyContinue
}
# Standard OAuth field names (RFC 6749): access_token, refresh_token. Never print the response itself:
# on success it contains live tokens
$json = $response | ConvertFrom-Json
if (-not $json.access_token) {
    $problem = if ($json.code) { "$($json.status) $($json.code): $($json.detail)" } else { 'unexpected response (not shown)' }
    throw "Exchange failed: $problem"
}

$claims = ConvertFrom-Base64Url ($json.access_token.Split('.')[1]) | ConvertFrom-Json
Write-Host "`nGoogle login worked. Access token (summary, token itself not shown):" -ForegroundColor Green
[pscustomobject]@{
    issuer       = $claims.iss
    subject      = $claims.sub
    email        = $claims.email
    roles        = ($claims.roles -join ', ')
    audience     = ($claims.aud -join ', ')
    expiresAt    = [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).LocalDateTime
    entitlements = ($claims.entitlements -join ', ')
    refreshToken = if ($json.refresh_token) { 'received (not shown)' } else { 'none' }
} | Format-List

# A test session should not stay alive: end it right away (logout revokes the refresh token)
$logout = Join-Path $env:TEMP 'swiftdrop-logout.json'
try {
    @{ refresh_token = $json.refresh_token } | ConvertTo-Json | Set-Content -Encoding ascii $logout
    $status = curl.exe -s -o NUL -w '%{http_code}' -H 'Content-Type: application/json' --data-binary "@$logout" "$BaseUrl/api/v1/auth/logout"
    Write-Host "Test session logged out (HTTP $status)."
} finally {
    Remove-Item $logout -ErrorAction SilentlyContinue
}
