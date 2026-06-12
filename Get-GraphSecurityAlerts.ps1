<#
.SYNOPSIS
    Retrieves Microsoft Graph security alerts (and optionally incidents) via
    the modern security API (alerts_v2). Read-only. PS 5.1 compatible.

.DESCRIPTION
    Companion to Invoke-GraphPermissionDiagnostics.ps1. Uses the same
    delegated Graph session (Connect-MgGraph) and only ever issues GETs.

    Requires delegated scope SecurityAlert.Read.All (and
    SecurityIncident.Read.All for -IncludeIncidents), plus a security role on
    the signed-in user (Security Reader, Security Operator, Compliance
    Administrator, or Global Reader).

.PARAMETER Days
    How many days back to fetch. Default 7.

.PARAMETER Severity
    Only return alerts of these severities. Default: all.

.PARAMETER Top
    Maximum alerts to return across all pages. Default 100.

.PARAMETER IncludeIncidents
    Also fetch security incidents for the same period.

.PARAMETER CsvPath
    Export the alerts to a CSV file at this path (incidents go to a second
    file with '-incidents' appended).

.EXAMPLE
    Connect-MgGraph -Scopes "SecurityAlert.Read.All","SecurityIncident.Read.All"
    .\Get-GraphSecurityAlerts.ps1 -Days 14 -Severity high,medium -IncludeIncidents

.EXAMPLE
    .\Get-GraphSecurityAlerts.ps1 -Days 30 -CsvPath .\alerts.csv
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$Days = 7,
    [ValidateSet('high', 'medium', 'low', 'informational')]
    [string[]]$Severity,
    [ValidateRange(1, 2000)]
    [int]$Top = 100,
    [switch]$IncludeIncidents,
    [string]$CsvPath
)

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
}
$ctx = Get-MgContext
if (-not $ctx) {
    throw 'No Graph session. Run: Connect-MgGraph -Scopes "SecurityAlert.Read.All","SecurityIncident.Read.All"'
}
$scopes = @()
if ($ctx.Scopes) { $scopes = @($ctx.Scopes) }
if (-not ($scopes -contains 'SecurityAlert.Read.All' -or $scopes -contains 'SecurityAlert.ReadWrite.All')) {
    Write-Warning 'SecurityAlert.Read.All is not in your token - the alerts call will likely 403. Reconnect with: Connect-MgGraph -Scopes "SecurityAlert.Read.All"'
}

function Get-GraphPages {
    # Follows @odata.nextLink until $Max items are collected.
    param([string]$Uri, [int]$Max)
    $items = New-Object System.Collections.ArrayList
    $next = $Uri
    while ($next -and $items.Count -lt $Max) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        if ($resp.value) {
            foreach ($v in $resp.value) {
                if ($items.Count -ge $Max) { break }
                [void]$items.Add($v)
            }
        }
        $next = $null
        if ($resp.ContainsKey('@odata.nextLink')) { $next = $resp.'@odata.nextLink' }
    }
    return ,$items
}

$since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
$filter = "createdDateTime ge $since"
if ($Severity) {
    $sevParts = @($Severity | ForEach-Object { "severity eq '{0}'" -f $_ })
    $filter = "{0} and ({1})" -f $filter, ($sevParts -join ' or ')
}

$pageSize = [Math]::Min($Top, 100)
$alertsUri = "/v1.0/security/alerts_v2?`$filter=$filter&`$orderby=createdDateTime desc&`$top=$pageSize"

Write-Host ('Fetching alerts since {0} (max {1})...' -f $since, $Top) -ForegroundColor Cyan
$alerts = @()
try {
    $alerts = Get-GraphPages -Uri $alertsUri -Max $Top
}
catch {
    $msg = $_.Exception.Message
    if ($msg -match '403|Forbidden') {
        Write-Error ("Graph returned 403. Your token has the scope, so this is a ROLE problem: activate Global Reader / Security Reader in PIM (Entra ID > Privileged Identity Management > My roles), wait a minute, then Disconnect-MgGraph, Connect-MgGraph and retry. Detail: {0}" -f $msg)
    }
    throw
}

if ($alerts.Count -eq 0) {
    Write-Host ('No alerts found in the last {0} day(s) with the given filters.' -f $Days) -ForegroundColor Green
}
else {
    $alertRows = $alerts | ForEach-Object {
        [pscustomobject]@{
            Created     = $_.createdDateTime
            Severity    = $_.severity
            Status      = $_.status
            Title       = $_.title
            Category    = $_.category
            Source      = $_.serviceSource
            User        = ($_.evidence | ForEach-Object { if ($_.ContainsKey('userAccount') -and $_.userAccount) { $_.userAccount.userPrincipalName } } | Where-Object { $_ } | Select-Object -First 1)
            AlertId     = $_.id
            IncidentId  = $_.incidentId
        }
    }
    Write-Host ('{0} alert(s):' -f $alertRows.Count) -ForegroundColor Cyan
    $alertRows | Sort-Object Created -Descending | Format-Table Created, Severity, Status, Title, Source, User -AutoSize -Wrap

    $bySeverity = $alertRows | Group-Object Severity | Sort-Object Count -Descending
    Write-Host ('By severity: {0}' -f (($bySeverity | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', ')) -ForegroundColor DarkGray

    if ($CsvPath) {
        $alertRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ('Alerts exported to {0}' -f (Resolve-Path $CsvPath)) -ForegroundColor Cyan
    }
}

if ($IncludeIncidents) {
    if (-not ($scopes -contains 'SecurityIncident.Read.All' -or $scopes -contains 'SecurityIncident.ReadWrite.All')) {
        Write-Warning 'SecurityIncident.Read.All is not in your token - the incidents call will likely 403.'
    }
    $incUri = "/v1.0/security/incidents?`$filter=createdDateTime ge $since&`$orderby=createdDateTime desc&`$top=$pageSize"
    Write-Host ''
    Write-Host ('Fetching incidents since {0}...' -f $since) -ForegroundColor Cyan
    $incidents = Get-GraphPages -Uri $incUri -Max $Top
    if ($incidents.Count -eq 0) {
        Write-Host ('No incidents in the last {0} day(s).' -f $Days) -ForegroundColor Green
    }
    else {
        $incRows = $incidents | ForEach-Object {
            [pscustomobject]@{
                Created    = $_.createdDateTime
                Severity   = $_.severity
                Status     = $_.status
                Name       = $_.displayName
                Determination = $_.determination
                AssignedTo = $_.assignedTo
                IncidentId = $_.id
                WebUrl     = $_.incidentWebUrl
            }
        }
        Write-Host ('{0} incident(s):' -f $incRows.Count) -ForegroundColor Cyan
        $incRows | Sort-Object Created -Descending | Format-Table Created, Severity, Status, Name, AssignedTo -AutoSize -Wrap

        if ($CsvPath) {
            $incCsv = [System.IO.Path]::ChangeExtension($CsvPath, $null).TrimEnd('.') + '-incidents.csv'
            $incRows | Export-Csv -Path $incCsv -NoTypeInformation -Encoding UTF8
            Write-Host ('Incidents exported to {0}' -f (Resolve-Path $incCsv)) -ForegroundColor Cyan
        }
    }
}
