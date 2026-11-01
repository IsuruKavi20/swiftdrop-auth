# Admin tool for the deployed service (no admin UI yet): find users, grant and remove roles.
#   powershell -ExecutionPolicy Bypass -File .\deploy\oke\admin.ps1
# You log in with Google as an ADMIN; every action is checked by the service itself (an admin can't remove their
# own ADMIN role, the last admin can't be removed, MERCHANT is only given through merchant approval).
param([string]$BaseUrl = 'https://auth.getswiftdrop.me')
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\swiftdrop-login.ps1"

$Roles = @('CUSTOMER', 'COURIER', 'DISPATCHER', 'ADMIN')

function Invoke-AdminApi([string]$method, [string]$path, [string]$token) {
    $raw = curl.exe -s -X $method -H "Authorization: Bearer $token" -w "`n%{http_code}" "$BaseUrl$path"
    $lines = @($raw -split "`n")
    $status = $lines[-1]
    $body = ($lines[0..($lines.Count - 2)] -join "`n") | ConvertFrom-Json
    if ($status -notmatch '^2') {
        $reason = if ($body.detail) { "$($body.code): $($body.detail)" } else { "HTTP $status" }
        Write-Host "Refused: $reason" -ForegroundColor Yellow
        return $null
    }
    return $body
}

function Show-User($user) {
    if ($user) {
        Write-Host ("{0}  verified={1}  status={2}  roles=[{3}]  id={4}" -f $user.email, $user.emailVerified, $user.status,
            ($user.roles -join ', '), $user.id) -ForegroundColor Green
    }
}

$tokens = Invoke-SwiftDropGoogleLogin $BaseUrl
$me = Get-AccessTokenClaims $tokens.access_token
# Access tokens carry no email (less personal data in every token): identify the account by its id
if ($me.roles -notcontains 'ADMIN') {
    Invoke-SwiftDropLogout $BaseUrl $tokens
    throw "This Google account (user id $($me.sub)) does not have the ADMIN role."
}
Write-Host "`nLogged in as ADMIN (user id $($me.sub))." -ForegroundColor Green
$started = Get-Date

try {
    while ($true) {
        # Access tokens live 15 minutes: start again rather than act with an expired one
        if (((Get-Date) - $started).TotalMinutes -gt 13) { Write-Host 'Session almost expired: run the script again.'; break }
        Write-Host "`n[1] Find a user   [2] Grant a role   [3] Remove a role   [q] Quit"
        $choice = Read-Host 'Choose'
        if ($choice -eq 'q') { break }
        if ($choice -notin @('1', '2', '3')) { continue }

        $email = (Read-Host 'User email').Trim()
        $user = Invoke-AdminApi GET "/api/v1/admin/users?email=$([uri]::EscapeDataString($email))" $tokens.access_token
        Show-User $user
        if (-not $user -or $choice -eq '1') { continue }

        $role = (Read-Host "Role ($($Roles -join '/'))").Trim().ToUpper()
        if ($role -notin $Roles) { Write-Host 'Unknown role.' -ForegroundColor Yellow; continue }
        $method = if ($choice -eq '2') { 'PUT' } else { 'DELETE' }
        if ((Read-Host "$method $role for $($user.email)? (y/n)") -ne 'y') { continue }
        Show-User (Invoke-AdminApi $method "/api/v1/admin/users/$($user.id)/roles/$role" $tokens.access_token)
    }
} finally {
    Invoke-SwiftDropLogout $BaseUrl $tokens
}
