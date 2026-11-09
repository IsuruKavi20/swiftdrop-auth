# Break-glass admin tool (identity step 9e; lesson 31). For when the SwiftDrop admin portal is down or broken.
# Needs YOUR cluster access (kubectl): there is no web page for this, so there is nothing on the internet to attack.
# Each action starts the auth image once as a short Kubernetes Job that runs the SAME rules as the portal (a reason
# is required, never the last admin, ...), writes an audit row as "break-glass", prints one result line and exits.
# Prints ids, statuses and roles only: never passwords or tokens.
#
#   .\deploy\oke\break-glass.ps1          the menu
#   .\deploy\oke\break-glass.ps1 -Help    what each action does
param(
    [switch] $Help,
    [string] $Namespace = "swiftdrop",
    [string] $Release = "auth"
)
$ErrorActionPreference = "Stop"

$actions = [ordered]@{
    "1" = @{ Name = "Find a user";             Command = "find";         Help = "Shows id, status, roles and open sessions (by email or id). Changes nothing." }
    "2" = @{ Name = "Block a user";            Command = "block";        Help = "No more logins, every session ends, SwiftDrop is told (account-disabled)." }
    "3" = @{ Name = "Unblock a user";          Command = "unblock";      Help = "The person can log in again." }
    "4" = @{ Name = "Delete a user";           Command = "delete";       Help = "Starts the erasure: tombstone now, gone everywhere within 30 days. Cannot be undone." }
    "5" = @{ Name = "Give a role";             Command = "grant";        Help = "Adds a role, e.g. ADMIN back when every admin is locked out. Not MERCHANT." }
    "6" = @{ Name = "Remove a role";           Command = "revoke";       Help = "Removes a role; the person's sessions end. Never the last ADMIN." }
    "7" = @{ Name = "End someone's sessions";  Command = "end-sessions"; Help = "Logs the person out on every device (e.g. a stolen phone)." }
    "8" = @{ Name = "Check the audit chain";   Command = "verify";       Help = "Recomputes the audit log's hash chain: OK, or the first changed row." }
}

function Show-Help {
    Write-Host "Break-glass admin tool. Use the SwiftDrop admin portal when it works; this is for emergencies."
    foreach ($key in $actions.Keys) { Write-Host ("  {0}  {1,-24} {2}" -f $key, $actions[$key].Name, $actions[$key].Help) }
    Write-Host "Every action except 1 and 8 asks for a reason (no email addresses in it) and for YES before it runs."
    Write-Host "Each action takes about a minute: the auth image starts once, does the one thing, and stops."
}

function Ask([string] $question) {
    do { $answer = (Read-Host $question).Trim() } until ($answer)
    return $answer
}

# Builds a one-off Job from the running Deployment (same image, same settings), runs it, returns its result line
function Invoke-BreakGlass([string] $command, [string] $user, [string] $role, [string] $reason) {
    $deployment = kubectl get deployment $Release -n $Namespace -o json | ConvertFrom-Json
    $pod = $deployment.spec.template
    $pod.metadata = [pscustomobject]@{ labels = [pscustomobject]@{
        "app.kubernetes.io/name" = "break-glass"; "app.kubernetes.io/instance" = $Release; "app.kubernetes.io/part-of" = "swiftdrop" } }
    $pod.spec | Add-Member -Force -NotePropertyName restartPolicy -NotePropertyValue "Never"
    $container = $pod.spec.containers[0]
    foreach ($field in "startupProbe", "readinessProbe", "livenessProbe", "lifecycle", "ports") { $container.PSObject.Properties.Remove($field) }
    $container.env = @($container.env) + @(
        [pscustomobject]@{ name = "SPRING_PROFILES_ACTIVE"; value = "prod,break-glass" },
        [pscustomobject]@{ name = "SERVER_PORT"; value = "0" },
        [pscustomobject]@{ name = "SWIFTDROP_BREAK_GLASS_COMMAND"; value = $command },
        [pscustomobject]@{ name = "SWIFTDROP_BREAK_GLASS_USER"; value = $user },
        [pscustomobject]@{ name = "SWIFTDROP_BREAK_GLASS_ROLE"; value = $role },
        [pscustomobject]@{ name = "SWIFTDROP_BREAK_GLASS_REASON"; value = $reason })
    $jobName = "$Release-break-glass-" + (Get-Date -Format "yyyyMMddHHmmss")
    $job = [pscustomobject]@{
        apiVersion = "batch/v1"; kind = "Job"
        metadata = [pscustomobject]@{ name = $jobName; namespace = $Namespace }
        spec = [pscustomobject]@{ backoffLimit = 0; activeDeadlineSeconds = 300; ttlSecondsAfterFinished = 600; template = $pod }
    }
    $file = Join-Path $env:TEMP "$jobName.json"
    try {
        $job | ConvertTo-Json -Depth 50 | Set-Content -Encoding utf8 $file
        kubectl apply -f $file | Out-Null
        Write-Host "Running (about a minute)..." -NoNewline
        do {
            Start-Sleep 5; Write-Host "." -NoNewline
            $status = kubectl get job $jobName -n $Namespace -o json | ConvertFrom-Json
        } until ($status.status.succeeded -or $status.status.failed)
        Write-Host ""
        # Production logs are JSON lines: take just the result text out of the line
        $match = kubectl logs "job/$jobName" -n $Namespace | Select-String -Pattern 'BREAK-GLASS (RESULT|FAILED): [^"]*' |
            Select-Object -Last 1
        if (-not $match) { return "BREAK-GLASS FAILED: no result (see: kubectl logs job/$jobName -n $Namespace)" }
        kubectl delete job $jobName -n $Namespace --wait=false | Out-Null
        return $match.Matches[0].Value
    }
    finally {
        Remove-Item -Force $file -ErrorAction SilentlyContinue
    }
}

if ($Help) { Show-Help; return }

while ($true) {
    Write-Host ""
    Write-Host "=== SwiftDrop auth: break-glass admin ===" -ForegroundColor Cyan
    foreach ($key in $actions.Keys) { Write-Host "  $key  $($actions[$key].Name)" }
    Write-Host "  0  Exit"
    $choice = (Read-Host "Choose").Trim()
    if ($choice -eq "0") { break }
    if (-not $actions.Contains($choice)) { Write-Host "Please type a number from the menu." -ForegroundColor Yellow; continue }
    $action = $actions[$choice]

    $user = ""; $role = ""; $reason = ""
    if ($action.Command -eq "find") { $user = Ask "Email or id" }
    elseif ($action.Command -ne "verify") { $user = Ask "User id (use 1 Find a user to get it)" }
    if ($action.Command -in "grant", "revoke") { $role = (Ask "Role (CUSTOMER, COURIER, DISPATCHER, ADMIN)").ToUpper() }
    if ($action.Command -notin "find", "verify") {
        $reason = Ask "Reason (3-200 characters, no email addresses)"
        Write-Host ""
        Write-Host "What will happen: $($action.Help)" -ForegroundColor Yellow
        Write-Host "  user: $user  $(if ($role) { "role: $role" })  reason: $reason"
        if ((Read-Host "Type YES to continue") -cne "YES") { Write-Host "Cancelled, nothing changed."; continue }
    }

    $result = Invoke-BreakGlass $action.Command $user $role $reason
    if ($result -like "BREAK-GLASS RESULT:*") { Write-Host $result -ForegroundColor Green }
    else { Write-Host $result -ForegroundColor Red }
}
