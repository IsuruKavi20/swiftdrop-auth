# Shared by the scripts in deploy/oke: a Google login against the deployed service, playing the frontend's part
# (PKCE secret, browser login, one-time code exchange). Dot-source it:  . "$PSScriptRoot\swiftdrop-login.ps1"
# Tokens stay in memory: never printed, never written to disk except a temp request body deleted right away.

function ConvertTo-Base64Url([byte[]]$bytes) {
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url([string]$text) {
    $padded = $text.Replace('-', '+').Replace('_', '/')
    $padded += '=' * ((4 - $padded.Length % 4) % 4)
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($padded))
}

# POST a JSON body (from a temp file: Windows PowerShell 5.1 mangles quotes in curl arguments)
function Invoke-JsonPost([string]$url, [hashtable]$body, [string]$bearer) {
    $file = Join-Path $env:TEMP "swiftdrop-$([guid]::NewGuid()).json"
    try {
        $body | ConvertTo-Json | Set-Content -Encoding ascii $file
        $headers = @('-H', 'Content-Type: application/json')
        if ($bearer) { $headers += @('-H', "Authorization: Bearer $bearer") }
        return curl.exe -s @headers --data-binary "@$file" $url
    } finally {
        Remove-Item $file -ErrorAction SilentlyContinue
    }
}

# Returns the token response (access_token, refresh_token, ...) of a fresh Google login
function Invoke-SwiftDropGoogleLogin([string]$BaseUrl) {
    $secret = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($secret)
    $verifier = ConvertTo-Base64Url $secret
    $challenge = ConvertTo-Base64Url ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))

    Write-Host "`nOpening Google login in your browser..." -ForegroundColor Cyan
    Start-Process "$BaseUrl/oauth2/authorization/google?code_challenge=$challenge"
    Write-Host 'Log in. The browser then shows "can''t reach this page" at localhost:5173 - that is expected.'
    $pasted = (Read-Host 'Paste the address (or just the code after #code=), then press Enter (within 60 s)').Trim()

    if ($pasted -match 'error=') { throw "The service reported a failed Google login: $pasted" }
    if ($pasted -match 'code=([A-Za-z0-9_-]+)') { $code = $Matches[1] }
    elseif ($pasted -match '^[A-Za-z0-9_-]{20,64}$') { $code = $pasted }
    else { throw 'No code found in what you pasted.' }

    # Standard OAuth field names (RFC 6749). Never print the response: it holds live tokens
    $json = Invoke-JsonPost "$BaseUrl/api/v1/auth/google/exchange" @{ code = $code; verifier = $verifier } | ConvertFrom-Json
    if (-not $json.access_token) {
        $problem = if ($json.code) { "$($json.status) $($json.code): $($json.detail)" } else { 'unexpected response (not shown)' }
        throw "Exchange failed: $problem"
    }
    return $json
}

function Get-AccessTokenClaims([string]$accessToken) {
    return ConvertFrom-Base64Url ($accessToken.Split('.')[1]) | ConvertFrom-Json
}

# Ends the session: the refresh token is revoked (an access token dies by itself within 15 minutes)
function Invoke-SwiftDropLogout([string]$BaseUrl, $tokens) {
    $file = Join-Path $env:TEMP "swiftdrop-$([guid]::NewGuid()).json"
    try {
        @{ refresh_token = $tokens.refresh_token } | ConvertTo-Json | Set-Content -Encoding ascii $file
        $status = curl.exe -s -o NUL -w '%{http_code}' -H 'Content-Type: application/json' --data-binary "@$file" "$BaseUrl/api/v1/auth/logout"
        Write-Host "Session logged out (HTTP $status)."
    } finally {
        Remove-Item $file -ErrorAction SilentlyContinue
    }
}
