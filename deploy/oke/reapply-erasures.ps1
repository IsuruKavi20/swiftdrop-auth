# Re-apply erasures after restoring a backup (identity step 8; lesson 29). A restored backup may contain people who
# deleted their account AFTER that backup was made. The nightly job also stores the list of deleted ids
# (erasures/<stamp>.csv.age); this script downloads the newest list with YOUR Oracle login, decrypts it with YOUR
# private key on this laptop, and erases every listed person again in production (row + cascades, erasure_log line).
# Run it right after any restore, BEFORE the app is opened to users again.
#
#   .\deploy\oke\reapply-erasures.ps1 -KeyFile "C:\Users\USER\keys\swiftdrop-backup-key.txt" -Namespace ax8lt6cfwnh8
param(
    [Parameter(Mandatory)] [string] $KeyFile,
    [Parameter(Mandatory)] [string] $Namespace,
    [string] $Bucket = "swiftdrop-auth-backups",
    [string] $Age = "$HOME\tools\age\age\age.exe"
)
$ErrorActionPreference = "Stop"
$work = Join-Path $env:TEMP "reapply-erasures-$PID"
New-Item -ItemType Directory -Force $work | Out-Null

try {
    $newest = (oci os object list --namespace $Namespace --bucket-name $Bucket --prefix erasures/ --all `
        --query 'data[].name' --raw-output | ConvertFrom-Json) | Sort-Object | Select-Object -Last 1
    if (-not $newest) { throw "No erasure list found in $Bucket/erasures/" }
    Write-Host "Newest erasure list: $newest"
    oci os object get --namespace $Namespace --bucket-name $Bucket --name $newest --file "$work\list.age" | Out-Null
    & $Age --decrypt -i $KeyFile -o "$work\list.csv" "$work\list.age"

    # Only well-formed ids reach the database (the file is ours, but nothing is trusted blindly)
    $ids = Get-Content "$work\list.csv" | ForEach-Object { ($_ -split ',')[0].Trim() } |
        Where-Object { $_ -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' } | Sort-Object -Unique
    Write-Host "Deleted people in the list: $($ids.Count)"
    if ($ids.Count -eq 0) { Write-Host "Nothing to re-apply."; return }

    $values = ($ids | ForEach-Object { "('$_'::uuid)" }) -join ","
    $sql = @"
BEGIN;
WITH listed(id) AS (VALUES $values),
     back AS (SELECT u.id, coalesce(u.deleted_at, now()) AS deleted_at FROM identity.users u JOIN listed l ON l.id = u.id)
INSERT INTO identity.erasure_log (user_id, deleted_at, erased_at, complete)
SELECT id, deleted_at, now(), false FROM back ON CONFLICT (user_id) DO NOTHING;
DELETE FROM identity.users WHERE id IN (SELECT id FROM (VALUES $values) AS listed(id));
COMMIT;
"@
    $sql | kubectl exec -i -n swiftdrop auth-postgres-0 -- psql -v ON_ERROR_STOP=1 -U postgres -d identity
    Write-Host "Done: every listed person is erased again (they had come back with the restored backup)." -ForegroundColor Green
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
