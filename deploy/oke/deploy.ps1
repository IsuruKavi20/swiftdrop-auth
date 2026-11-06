# Deploys SwiftDrop auth onto the Oracle OKE cluster (lesson 17). Run from E:\EAD in PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\deploy\oke\deploy.ps1
# Needs: kubectl pointing at OKE, cert-manager + Traefik + Reloader installed (lesson 17, step B3).
# Re-runnable: existing Secrets are kept (new passwords would not match the existing database).
# Asks for two personal values, so they are never written into any file:
#   - your email (Let's Encrypt sends certificate-expiry warnings there)
#   - an OCIR auth token (the cluster uses it to download our private image)
$ErrorActionPreference = 'Stop'
if ($env:Path -notlike '*C:\tools*') { $env:Path += ';C:\tools' }

$Namespace = 'swiftdrop'
$Registry = 'hyd.ocir.io'
$RegistryUser = 'ax8lt6cfwnh8/isurukpremasiri2001@gmail.com'

function Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }
function Check { if ($LASTEXITCODE -ne 0) { throw "Last command failed (exit code $LASTEXITCODE)" } }
function New-Password { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ }) }
function Test-Exists {
    $ErrorActionPreference = 'Continue'
    & kubectl get @args 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

Step 'Which cluster?'
$context = kubectl config current-context; Check
Write-Host "kubectl talks to: $context"
if ($context -like 'kind-*') { throw 'This is the laptop (kind) cluster. Switch to Oracle first: kubectl config use-context <context-swiftdrop-...>' }

Step "Let's Encrypt issuer"
$email = Read-Host 'Your email for Let''s Encrypt expiry notices'
if ($email -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw 'That does not look like an email address' }
(Get-Content deploy/oke/letsencrypt-issuer.yaml -Raw) -replace 'CHANGE-ME@example.com', $email | kubectl apply -f -; Check

Step 'Disk type for Postgres (paravirtualized, works with in-transit encryption)'
kubectl apply -f deploy/oke/storageclass.yaml; Check

Step 'Namespace with Pod Security "restricted"'
if (-not (Test-Exists namespace $Namespace)) { kubectl create namespace $Namespace; Check }
kubectl label namespace $Namespace pod-security.kubernetes.io/enforce=restricted --overwrite; Check

Step 'Registry login for the cluster (ocir-pull)'
if (Test-Exists secret ocir-pull -n $Namespace) {
    Write-Host 'ocir-pull already exists: keeping it'
} else {
    # Pasting into a hidden prompt is unreliable in Windows PowerShell 5.1 (only the first character arrived),
    # so the token is read straight from the clipboard: copy it, then press Enter here
    Read-Host 'Copy your OCIR auth token to the clipboard, then press Enter' | Out-Null
    $token = (Get-Clipboard -Raw).Trim()
    if ($token.Length -lt 10) { throw "The clipboard doesn't hold a token (length $($token.Length)). Copy it again." }
    kubectl create secret docker-registry ocir-pull -n $Namespace --docker-server=$Registry `
        --docker-username=$RegistryUser --docker-password=$token | Out-Null; Check
    $token = $null
    Set-Clipboard -Value ' '   # don't leave the token in the clipboard
}

Step 'App secrets (random passwords nobody sees + a new signing key)'
if (Test-Exists secret swiftdrop-auth-secrets -n $Namespace) {
    Write-Host 'swiftdrop-auth-secrets already exists: keeping it'
} else {
    $envFile = Get-Content .env | Where-Object { $_ -match '^\s*[A-Z_]+=' } | ConvertFrom-StringData
    kubectl create secret generic swiftdrop-auth-secrets -n $Namespace `
        --from-literal=db-admin-password=$(New-Password) `
        --from-literal=db-migrator-password=$(New-Password) `
        --from-literal=db-app-password=$(New-Password) `
        --from-literal=redis-password=$(New-Password) `
        --from-literal=mail-username=swiftdrop `
        --from-literal=mail-password=$(New-Password) `
        --from-literal=google-client-id=$($envFile.GOOGLE_CLIENT_ID) `
        --from-literal=google-client-secret=$($envFile.GOOGLE_CLIENT_SECRET) | Out-Null; Check
}
if (Test-Exists secret swiftdrop-auth-jwt -n $Namespace) {
    Write-Host 'swiftdrop-auth-jwt already exists: keeping it'
} else {
    $keyFile = Join-Path $env:TEMP 'signing-key.pem'
    try {
        & 'C:\Program Files\Git\usr\bin\openssl.exe' genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out $keyFile; Check
        kubectl create secret generic swiftdrop-auth-jwt -n $Namespace --from-file=signing-key.pem=$keyFile | Out-Null; Check
    } finally {
        Remove-Item $keyFile -ErrorAction SilentlyContinue
    }
}

Step 'SwiftDrop auth (our Helm chart)'
helm upgrade --install auth deploy/helm/swiftdrop-auth -n $Namespace `
    -f deploy/helm/swiftdrop-auth/values-oracle.yaml --wait --timeout 15m; Check

Step 'Done'
kubectl get pods -n $Namespace -o wide
kubectl get certificate -n $Namespace
Write-Host "`nTry: https://auth.getswiftdrop.me/.well-known/jwks.json" -ForegroundColor Green
