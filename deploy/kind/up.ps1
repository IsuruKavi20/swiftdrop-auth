# Builds the whole local Kubernetes set-up (lesson 17/18): cluster, add-ons, secrets, image, our chart.
# Run from E:\EAD in PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\deploy\kind\up.ps1          # create, or continue / update
#   powershell -ExecutionPolicy Bypass -File .\deploy\kind\up.ps1 -Fresh   # delete everything and start over
# Re-runnable: every step checks what already exists, so after an error just run it again.
# A multi-node kind cluster does NOT survive a Docker restart (node IPs change): use -Fresh after one.
param([switch]$Fresh)
$ErrorActionPreference = 'Stop'

# Pinned versions: a new chart version can rename settings (it happened with Traefik 42)
$CertManagerVersion = 'v1.18.2'
$TraefikVersion = '42.2.0'
$ReloaderVersion = '2.2.19'
$Image = 'swiftdrop-auth:1.1.0-local'
$Wait = '10m'   # first image downloads can be slow

# The tools live in C:\tools; make sure this window can find them
if ($env:Path -notlike '*C:\tools*') { $env:Path += ';C:\tools' }

function Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }
# Native tools don't throw in PowerShell 5.1: stop on a non-zero exit code ourselves
function Check { if ($LASTEXITCODE -ne 0) { throw "Last command failed (exit code $LASTEXITCODE)" } }
function New-Password { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ }) }
# "Not found" is an answer here, not an error (PowerShell 5.1 would otherwise stop on the tool's error text)
function Test-Exists {
    $ErrorActionPreference = 'Continue'
    & kubectl get @args 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}
function Get-KindClusters {
    $ErrorActionPreference = 'Continue'
    return @(kind get clusters 2>&1 | ForEach-Object { "$_" })
}

Step 'Cluster (1 control plane + 2 workers)'
$clusters = Get-KindClusters
if ($Fresh -and ($clusters -contains 'swiftdrop')) {
    kind delete cluster --name swiftdrop; Check
    $clusters = @()
}
if ($clusters -contains 'swiftdrop') {
    # A cluster that Docker brought back after a restart can be half-alive: then start over automatically
    $ErrorActionPreference = 'Continue'
    kind export kubeconfig --name swiftdrop 2>&1 | Out-Null
    $healthy = ($LASTEXITCODE -eq 0)
    if ($healthy) { kubectl get nodes --request-timeout=15s 2>&1 | Out-Null; $healthy = ($LASTEXITCODE -eq 0) }
    $ErrorActionPreference = 'Stop'
    if ($healthy) {
        Write-Host 'Cluster already exists and answers: keeping it (use -Fresh to start over)'
    } else {
        Write-Host 'Cluster exists but is broken (e.g. after a Docker restart): deleting and recreating it' -ForegroundColor Yellow
        kind delete cluster --name swiftdrop; Check
        $clusters = @()
    }
}
if (-not ($clusters -contains 'swiftdrop')) {
    kind create cluster --config deploy/kind/cluster.yaml; Check
}
kubectl wait --for=condition=Ready nodes --all --timeout=180s; Check

Step 'Chart repositories'
helm repo add jetstack https://charts.jetstack.io --force-update | Out-Null; Check
helm repo add traefik https://traefik.github.io/charts --force-update | Out-Null; Check
helm repo add stakater https://stakater.github.io/stakater-charts --force-update | Out-Null; Check
helm repo update | Out-Null; Check

Step "cert-manager $CertManagerVersion (certificate robot)"
helm upgrade --install cert-manager jetstack/cert-manager -n cert-manager --create-namespace `
    --version $CertManagerVersion --set crds.enabled=true --wait --timeout $Wait; Check

Step "Traefik $TraefikVersion (front door)"
helm upgrade --install traefik traefik/traefik -n traefik --create-namespace --version $TraefikVersion `
    -f deploy/kind/traefik-values.yaml --wait --timeout $Wait; Check

Step "Reloader $ReloaderVersion (restarts pods when their Secrets change)"
helm upgrade --install reloader stakater/reloader -n reloader --create-namespace `
    --version $ReloaderVersion --wait --timeout $Wait; Check

Step 'Namespace with Pod Security "restricted"'
if (-not (Test-Exists namespace swiftdrop)) { kubectl create namespace swiftdrop; Check }
kubectl label namespace swiftdrop pod-security.kubernetes.io/enforce=restricted --overwrite; Check

Step 'Secrets (random passwords nobody sees + a new signing key)'
# Only when missing: new passwords would no longer match the ones the existing database was created with
if (Test-Exists secret swiftdrop-auth-secrets -n swiftdrop) {
    Write-Host 'swiftdrop-auth-secrets already exists: keeping it'
} else {
    $envFile = Get-Content .env | Where-Object { $_ -match '^\s*[A-Z_]+=' } | ConvertFrom-StringData
    kubectl create secret generic swiftdrop-auth-secrets -n swiftdrop `
        --from-literal=db-admin-password=$(New-Password) `
        --from-literal=db-migrator-password=$(New-Password) `
        --from-literal=db-app-password=$(New-Password) `
        --from-literal=redis-password=$(New-Password) `
        --from-literal=mail-username=swiftdrop `
        --from-literal=mail-password=$(New-Password) `
        --from-literal=google-client-id=$($envFile.GOOGLE_CLIENT_ID) `
        --from-literal=google-client-secret=$($envFile.GOOGLE_CLIENT_SECRET) | Out-Null; Check
}
if (Test-Exists secret swiftdrop-auth-jwt -n swiftdrop) {
    Write-Host 'swiftdrop-auth-jwt already exists: keeping it'
} else {
    $keyFile = Join-Path $env:TEMP 'signing-key.pem'
    try {
        & 'C:\Program Files\Git\usr\bin\openssl.exe' genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out $keyFile; Check
        kubectl create secret generic swiftdrop-auth-jwt -n swiftdrop --from-file=signing-key.pem=$keyFile | Out-Null; Check
    } finally {
        Remove-Item $keyFile -ErrorAction SilentlyContinue
    }
}

Step "Image $Image"
docker build -t $Image .; Check
kind load docker-image $Image --name swiftdrop; Check

Step 'SwiftDrop auth (our Helm chart)'
helm upgrade --install auth deploy/helm/swiftdrop-auth -n swiftdrop `
    -f deploy/helm/swiftdrop-auth/values-local.yaml --wait --timeout $Wait; Check
# Same image tag, new content: restart so the pods run the image we just loaded
kubectl rollout restart deployment/auth -n swiftdrop; Check
kubectl rollout status deployment/auth -n swiftdrop --timeout=600s; Check

Step 'Done'
kubectl get pods -n swiftdrop -o wide
Write-Host "`nTry: https://auth.127.0.0.1.nip.io:8443/.well-known/jwks.json" -ForegroundColor Green
Write-Host 'Stop for the day: kind delete cluster --name swiftdrop   (next time: run this script again)'
