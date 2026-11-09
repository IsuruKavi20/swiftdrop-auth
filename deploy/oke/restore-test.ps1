# Restore test (plan/STEP-BACKUPS.md, B2; lesson 28): proves the newest production backup can really be restored.
# Downloads it with YOUR Oracle login (the cluster's key can't read backups), decrypts it with YOUR private key on this
# laptop, restores it into a throwaway Postgres in Docker, and compares the user count with production.
# Everything temporary (container, downloaded file) is removed at the end.
#
#   .\deploy\oke\restore-test.ps1 -KeyFile "$HOME\Documents\swiftdrop-backup-key.txt" -Namespace <object storage namespace>
param(
    [Parameter(Mandatory)] [string] $KeyFile,
    [Parameter(Mandatory)] [string] $Namespace,
    [string] $Bucket = "swiftdrop-auth-backups",
    [string] $Image = "docker.io/library/postgres:17-alpine"
)
$ErrorActionPreference = "Stop"
$work = Join-Path $env:TEMP "restore-test-$PID"
$container = "restore-test-$PID"
New-Item -ItemType Directory -Force $work | Out-Null

try {
    # 1. The newest daily backup
    $newest = (oci os object list --namespace $Namespace --bucket-name $Bucket --prefix daily/ --all `
        --query 'data[].name' --raw-output | ConvertFrom-Json) | Sort-Object | Select-Object -Last 1
    if (-not $newest) { throw "No backup found in $Bucket/daily/" }
    Write-Host "Newest backup: $newest"
    $file = Join-Path $work "backup.age"
    oci os object get --namespace $Namespace --bucket-name $Bucket --name $newest --file $file | Out-Null

    # 2. A throwaway Postgres (with age added) to decrypt and restore into
    docker run -d --name $container -e POSTGRES_PASSWORD=restore -e POSTGRES_DB=restored $Image | Out-Null
    docker exec $container apk add --no-cache age | Out-Null
    do { Start-Sleep 1; docker exec $container pg_isready -U postgres -d restored *> $null } until ($LASTEXITCODE -eq 0)
    Start-Sleep 2
    docker cp $file "${container}:/tmp/backup.age"
    docker cp $KeyFile "${container}:/tmp/key.txt"

    # 3. Decrypt + restore (inside the throwaway container only)
    docker exec $container sh -c "age --decrypt -i /tmp/key.txt /tmp/backup.age | pg_restore -U postgres -d restored --no-owner --no-acl"
    $restored = (docker exec $container psql -tA -U postgres -d restored -c "SELECT count(*) FROM identity.users").Trim()

    # 4. Compare with production right now
    $live = (kubectl exec -n swiftdrop auth-postgres-0 -- psql -tA -U postgres -d identity -c "SELECT count(*) FROM identity.users").Trim()
    Write-Host "Users in the backup: $restored   Users in production now: $live"
    if ([int]$restored -gt 0 -and [int]$restored -le [int]$live) {
        Write-Host "PASS: the backup restores (production may have a few newer sign-ups since last night)" -ForegroundColor Green
    } else {
        Write-Host "FAIL: check the backup job (kubectl get jobs -n swiftdrop)" -ForegroundColor Red
        exit 1
    }
}
finally {
    docker rm -f $container *> $null
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
