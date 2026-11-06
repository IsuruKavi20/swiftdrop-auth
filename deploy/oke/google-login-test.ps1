# End-to-end Google login against the deployed service, playing the frontend's part (lesson 17).
#   powershell -ExecutionPolicy Bypass -File .\deploy\oke\google-login-test.ps1
# Shows only a summary of the access token's claims, then logs the test session out.
param([string]$BaseUrl = 'https://auth.getswiftdrop.me')
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\swiftdrop-login.ps1"

$tokens = Invoke-SwiftDropGoogleLogin $BaseUrl
$claims = Get-AccessTokenClaims $tokens.access_token
Write-Host "`nGoogle login worked. Access token (summary, token itself not shown):" -ForegroundColor Green
[pscustomobject]@{
    issuer       = $claims.iss
    subject      = $claims.sub
    roles        = ($claims.roles -join ', ')
    entitlements = ($claims.entitlements -join ', ')
    audience     = ($claims.aud -join ', ')
    expiresAt    = [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).LocalDateTime
    refreshToken = if ($tokens.refresh_token) { 'received (not shown)' } else { 'none' }
} | Format-List
Invoke-SwiftDropLogout $BaseUrl $tokens
