<#
.SYNOPSIS
    Diagnoses Microsoft Graph API permission and token problems for the
    Microsoft Graph PowerShell SDK on Windows PowerShell 5.1.

.DESCRIPTION
    Runs layered, read-only checks and reports PASS/WARN/FAIL with concrete
    remediation steps:

      1. Environment   - PS / .NET / TLS 1.2 / proxy / Graph module versions
      2. Connectivity  - TCP 443 to login.microsoftonline.com & graph.microsoft.com
      3. Token (401)   - Get-MgContext, delegated auth sanity, live /me smoke test
      4. Probes (403)  - representative Graph calls vs scopes in the token
      5. Targeted      - required permissions for a specific cmdlet or URI
      6. Consent       - tenant/user OAuth2 grants for the client app (best effort)

    Every layer is independently error-handled; one failure never aborts the run.
    The script makes no changes to the tenant or the local machine.

.PARAMETER Cmdlet
    Diagnose a specific failing SDK cmdlet (e.g. Get-MgUser). Looks up the
    permissions it requires and diffs them against the current session scopes.

.PARAMETER Uri
    Diagnose a specific failing Graph URI (e.g. /users or /me/messages).
    Use with -Method if it is not a GET.

.PARAMETER Method
    HTTP method for -Uri lookup. Default GET.

.PARAMETER SkipProbes
    Skip the live permission probe battery (layer 4).

.PARAMETER ReportPath
    Also write the full report to a plain-text file at this path.

.EXAMPLE
    .\Invoke-GraphPermissionDiagnostics.ps1

.EXAMPLE
    .\Invoke-GraphPermissionDiagnostics.ps1 -Cmdlet Get-MgGroupMember

.EXAMPLE
    .\Invoke-GraphPermissionDiagnostics.ps1 -Uri '/auditLogs/signIns' -ReportPath .\graph-diag.txt
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Cmdlet,
    [string]$Uri,
    [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
    [string]$Method = 'GET',
    [switch]$SkipProbes,
    [string]$ReportPath
)

# StrictMode 1.0 only: 2.0+ faults on properties absent from older SDK
# context objects (e.g. TokenCredentialType pre-v2), and this tool must
# never crash on the machines it is diagnosing.
Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

$script:Results = New-Object System.Collections.ArrayList
$script:ReportLines = New-Object System.Collections.ArrayList
$script:MissingScopes = New-Object System.Collections.ArrayList

#region Output helpers ------------------------------------------------------

function Write-Line {
    param([string]$Text, [ConsoleColor]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
    [void]$script:ReportLines.Add($Text)
}

function Write-Section {
    param([string]$Title)
    Write-Line ''
    Write-Line ('=== {0} ===' -f $Title) 'Cyan'
}

function Write-Result {
    param(
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')]
        [string]$Level,
        [string]$Area,
        [string]$Message,
        [string]$Fix
    )
    $color = 'Gray'
    switch ($Level) {
        'PASS' { $color = 'Green' }
        'WARN' { $color = 'Yellow' }
        'FAIL' { $color = 'Red' }
    }
    Write-Line ('[{0}] {1}: {2}' -f $Level, $Area, $Message) $color
    if ($Fix) {
        Write-Line ('       fix: {0}' -f $Fix) 'DarkGray'
    }
    [void]$script:Results.Add([pscustomobject]@{
            Level = $Level; Area = $Area; Message = $Message; Fix = $Fix
        })
}

#endregion

#region Error explanation ---------------------------------------------------

$script:AadstsHints = @{
    'AADSTS50034'  = 'The account does not exist in this tenant. Check you are signing in to the right tenant (Connect-MgGraph -TenantId <tenant>).'
    'AADSTS50053'  = 'Account is locked (smart lockout) or sign-in was blocked.'
    'AADSTS50055'  = 'Password is expired.'
    'AADSTS50057'  = 'The user account is disabled.'
    'AADSTS50058'  = 'Silent sign-in failed; interactive sign-in is required. Run Connect-MgGraph again interactively.'
    'AADSTS50076'  = 'Multi-factor authentication is required. Sign in interactively so MFA can complete.'
    'AADSTS50079'  = 'The user must enrol for multi-factor authentication.'
    'AADSTS50105'  = 'The signed-in user is not assigned to a role/app assignment for this application.'
    'AADSTS50126'  = 'Invalid username or password.'
    'AADSTS50128'  = 'Tenant could not be determined from the sign-in identifier.'
    'AADSTS50146'  = 'The application is configured for a different tenant.'
    'AADSTS53003'  = 'Blocked by a Conditional Access policy. Check Entra ID > Sign-in logs for the failing policy (device compliance, location, etc.).'
    'AADSTS530003' = 'Conditional Access requires a managed/compliant device.'
    'AADSTS65001'  = 'Consent has not been granted for one of the requested scopes. A user (or admin, for admin-restricted scopes) must consent. Re-run Connect-MgGraph with the scope and accept the prompt, or ask an admin to grant consent.'
    'AADSTS650057' = 'Invalid resource/scope requested. Check the scope names passed to Connect-MgGraph.'
    'AADSTS70011'  = 'The scope value in the request is not valid.'
    'AADSTS700016' = 'The application (client id) was not found in the tenant. Wrong -ClientId or wrong -TenantId.'
    'AADSTS7000218' = 'The app registration is not enabled as a public client. In the app registration, set "Allow public client flows" to Yes (Authentication blade).'
    'AADSTS700082' = 'The refresh token has expired. Run Disconnect-MgGraph then Connect-MgGraph to sign in again.'
    'AADSTS90002'  = 'Tenant not found. Check the -TenantId value.'
    'AADSTS500011' = 'The resource principal (Microsoft Graph) was not found in the tenant - usually a wrong tenant id.'
}

function Get-GraphErrorHint {
    # Returns a plain-English explanation for AADSTS / Graph error text, or $null.
    param([string]$Text)
    if (-not $Text) { return $null }
    $hints = New-Object System.Collections.ArrayList
    foreach ($m in [regex]::Matches($Text, 'AADSTS\d+')) {
        $code = $m.Value
        if ($script:AadstsHints.ContainsKey($code)) {
            [void]$hints.Add(('{0}: {1}' -f $code, $script:AadstsHints[$code]))
        }
        else {
            [void]$hints.Add(('{0}: look it up at https://login.microsoftonline.com/error?code={1}' -f $code, $code.Substring(6)))
        }
    }
    if ($Text -match 'Authorization_RequestDenied|Insufficient privileges') {
        [void]$hints.Add('Authorization_RequestDenied (403): the token was accepted but lacks a required permission. The scope is missing from the token, or consent was never granted, or the resource needs an admin role as well as the scope.')
    }
    if ($Text -match 'InvalidAuthenticationToken|CompactToken|Lifetime validation failed') {
        [void]$hints.Add('InvalidAuthenticationToken (401): the token is missing, malformed or expired. Run Disconnect-MgGraph then Connect-MgGraph. Also check the machine clock - more than ~5 minutes of skew invalidates tokens.')
    }
    if ($hints.Count -eq 0) { return $null }
    return ($hints -join ' | ')
}

function Get-FailureKind {
    # Classifies an exception from a Graph call as Unauthorized / Forbidden /
    # NotFound / Other based on whatever detail PS 5.1 gives us.
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    $text = $ErrorRecord.Exception.Message
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $text = $text + ' ' + $ErrorRecord.ErrorDetails.Message
    }
    $kind = 'Other'
    if ($text -match '\b401\b|Unauthorized|InvalidAuthenticationToken') { $kind = 'Unauthorized' }
    elseif ($text -match '\b403\b|Forbidden|Authorization_RequestDenied|Insufficient privileges') { $kind = 'Forbidden' }
    elseif ($text -match '\b404\b|NotFound|ResourceNotFound') { $kind = 'NotFound' }
    return [pscustomobject]@{ Kind = $kind; Text = $text }
}

#endregion

#region Layer 1: Environment ------------------------------------------------

function Test-Environment {
    Write-Section 'Layer 1: Environment'

    # PowerShell version
    $psv = $PSVersionTable.PSVersion
    if ($psv.Major -eq 5 -and $psv.Minor -ge 1) {
        Write-Result PASS 'PowerShell' ('Windows PowerShell {0}' -f $psv)
    }
    elseif ($psv.Major -ge 7) {
        Write-Result INFO 'PowerShell' ('Running under PowerShell {0} (script targets 5.1 but checks still apply)' -f $psv)
    }
    else {
        Write-Result FAIL 'PowerShell' ('Version {0} is below 5.1' -f $psv) 'Install Windows Management Framework 5.1 or PowerShell 7.'
    }

    # .NET Framework release (4.7.2+ needed by the Graph SDK on PS 5.1)
    if ($psv.Major -eq 5) {
        try {
            $rel = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction Stop).Release
            if ($rel -ge 461808) {
                Write-Result PASS '.NET Framework' ('Release {0} (>= 4.7.2)' -f $rel)
            }
            else {
                Write-Result FAIL '.NET Framework' ('Release {0} is older than 4.7.2; the Microsoft.Graph SDK requires 4.7.2+' -f $rel) 'Install .NET Framework 4.7.2 or later, then restart PowerShell.'
            }
        }
        catch {
            Write-Result WARN '.NET Framework' 'Could not read the .NET 4.x release key (non-Windows host or restricted registry).'
        }
    }

    # TLS 1.2 - the classic PS 5.1 failure: defaults to SSL3/TLS1.0 and every
    # HTTPS call to Entra/Graph dies with "Could not create SSL/TLS secure channel".
    $proto = [Net.ServicePointManager]::SecurityProtocol
    $protoText = $proto.ToString()
    if ($protoText -match 'Tls12|Tls13' -or $protoText -eq 'SystemDefault') {
        Write-Result PASS 'TLS' ('SecurityProtocol = {0}' -f $protoText)
    }
    else {
        Write-Result FAIL 'TLS' ('SecurityProtocol = {0} - TLS 1.2 is not enabled in this session' -f $protoText) "Run: [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12  (add to your profile, or set HKLM SchUseStrongCrypto=1 for .NET-wide default)"
    }
    if ($psv.Major -eq 5) {
        try {
            $sc = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name SchUseStrongCrypto -ErrorAction SilentlyContinue
            if (-not $sc -or $sc.SchUseStrongCrypto -ne 1) {
                Write-Result WARN 'TLS' 'SchUseStrongCrypto is not set machine-wide; only this session''s SecurityProtocol setting protects you.' 'Set HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 SchUseStrongCrypto (DWORD) = 1 (and the WOW6432Node twin) to make TLS 1.2 the .NET default.'
            }
        }
        catch {
            Write-Verbose ('SchUseStrongCrypto check skipped: {0}' -f $_.Exception.Message)
        }
    }

    # Proxy
    try {
        $proxy = [System.Net.WebRequest]::GetSystemWebProxy()
        $graphUri = [uri]'https://graph.microsoft.com'
        $via = $proxy.GetProxy($graphUri)
        if ($via -and $via.Host -ne $graphUri.Host) {
            Write-Result WARN 'Proxy' ('Traffic to graph.microsoft.com routes via proxy {0}' -f $via) 'If sign-in or Graph calls hang/fail, check the proxy allows login.microsoftonline.com and graph.microsoft.com and that authentication to the proxy works.'
        }
        else {
            Write-Result PASS 'Proxy' 'No system proxy in the path to graph.microsoft.com'
        }
    }
    catch {
        Write-Result INFO 'Proxy' ('Could not evaluate system proxy: {0}' -f $_.Exception.Message)
    }

    # Graph SDK modules + mixed-version detection
    $mods = @(Get-Module -ListAvailable -Name 'Microsoft.Graph.*' | Where-Object { $_.Name -ne 'Microsoft.Graph' })
    $auth = @($mods | Where-Object { $_.Name -eq 'Microsoft.Graph.Authentication' })
    if ($auth.Count -eq 0) {
        Write-Result FAIL 'Modules' 'Microsoft.Graph.Authentication is not installed.' 'Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
        return
    }
    $authVersions = @($auth | Select-Object -ExpandProperty Version | Sort-Object -Descending -Unique)
    Write-Result PASS 'Modules' ('Microsoft.Graph.Authentication {0} installed' -f ($authVersions -join ', '))
    if ($authVersions.Count -gt 1) {
        Write-Result WARN 'Modules' 'Multiple versions of Microsoft.Graph.Authentication are installed; PowerShell may load a different one than your other Graph sub-modules expect.' 'Uninstall older versions: Uninstall-Module Microsoft.Graph.Authentication -RequiredVersion <old>'
    }
    $otherVersions = @($mods | Where-Object { $_.Name -ne 'Microsoft.Graph.Authentication' } |
            Select-Object -ExpandProperty Version | Sort-Object -Unique)
    if ($otherVersions.Count -gt 0) {
        $latestAuth = $authVersions[0]
        $mismatched = @($mods | Where-Object { $_.Name -ne 'Microsoft.Graph.Authentication' -and $_.Version.Major -ne $latestAuth.Major })
        if ($mismatched.Count -gt 0) {
            $names = ($mismatched | Select-Object -ExpandProperty Name -Unique | Select-Object -First 5) -join ', '
            Write-Result WARN 'Modules' ('Graph sub-modules with a different major version than Authentication {0}: {1}' -f $latestAuth, $names) 'Mixed major versions cause opaque auth/serialization errors. Update everything together: Update-Module Microsoft.Graph (or uninstall all Microsoft.Graph.* and reinstall).'
        }
        else {
            Write-Result PASS 'Modules' ('{0} Graph sub-module(s) present, versions consistent with Authentication' -f $otherVersions.Count)
        }
    }
}

#endregion

#region Layer 2: Connectivity -----------------------------------------------

function Test-Connectivity {
    Write-Section 'Layer 2: Connectivity'
    foreach ($endpoint in 'login.microsoftonline.com', 'graph.microsoft.com') {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $client.BeginConnect($endpoint, 443, $null, $null)
            $ok = $async.AsyncWaitHandle.WaitOne(5000, $false)
            if ($ok -and $client.Connected) {
                Write-Result PASS 'Network' ('TCP 443 to {0} reachable' -f $endpoint)
            }
            else {
                Write-Result FAIL 'Network' ('TCP 443 to {0} timed out after 5s' -f $endpoint) 'Check firewall/proxy egress rules for this host.'
            }
        }
        catch {
            Write-Result FAIL 'Network' ('TCP 443 to {0} failed: {1}' -f $endpoint, $_.Exception.Message) 'Check DNS resolution and firewall/proxy egress rules.'
        }
        finally {
            $client.Close()
        }
    }
}

#endregion

#region Layer 3: Token / context (401 layer) --------------------------------

function Test-GraphContext {
    Write-Section 'Layer 3: Token & session context (401 layer)'

    if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
        try {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        }
        catch {
            Write-Result FAIL 'Context' ('Cannot import Microsoft.Graph.Authentication: {0}' -f $_.Exception.Message) 'Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
            return $null
        }
    }

    $ctx = $null
    try { $ctx = Get-MgContext } catch { Write-Verbose ('Get-MgContext failed: {0}' -f $_.Exception.Message) }
    if (-not $ctx) {
        Write-Result FAIL 'Context' 'No Graph session. Get-MgContext returned nothing.' 'Run: Connect-MgGraph -Scopes "User.Read" (add the scopes your workload needs), then re-run this script in the same session.'
        return $null
    }

    Write-Result INFO 'Context' ('Account   : {0}' -f $ctx.Account)
    Write-Result INFO 'Context' ('Tenant    : {0}' -f $ctx.TenantId)
    Write-Result INFO 'Context' ('App       : {0} ({1})' -f $ctx.AppName, $ctx.ClientId)
    Write-Result INFO 'Context' ('AuthType  : {0} / {1}' -f $ctx.AuthType, $ctx.TokenCredentialType)

    if ($ctx.AuthType -eq 'Delegated') {
        Write-Result PASS 'Context' 'Auth type is Delegated, as expected for signed-in user flows.'
    }
    else {
        Write-Result WARN 'Context' ('Auth type is {0}, not Delegated. App-only sessions use Application permissions and ignore -Scopes; this script''s scope analysis assumes delegated.' -f $ctx.AuthType)
    }

    $scopes = @()
    if ($ctx.Scopes) { $scopes = @($ctx.Scopes | Sort-Object) }
    if ($scopes.Count -gt 0) {
        Write-Result INFO 'Context' ('Scopes in token ({0}): {1}' -f $scopes.Count, ($scopes -join ', '))
    }
    else {
        Write-Result WARN 'Context' 'The context reports no scopes at all - the token may be app-only or the session is stale.'
    }

    # Live smoke test: does the token work at all?
    try {
        $me = Invoke-MgGraphRequest -Method GET -Uri '/v1.0/me' -ErrorAction Stop
        Write-Result PASS 'Token' ('GET /me succeeded as {0}' -f $me.userPrincipalName)
    }
    catch {
        $f = Get-FailureKind $_
        $hint = Get-GraphErrorHint $f.Text
        switch ($f.Kind) {
            'Unauthorized' {
                Write-Result FAIL 'Token' 'GET /me returned 401 - the token itself is being rejected.' 'Run Disconnect-MgGraph then Connect-MgGraph to get a fresh token. Check the machine clock (w32tm /resync) - clock skew breaks token validation.'
            }
            'Forbidden' {
                Write-Result FAIL 'Token' 'GET /me returned 403 - even User.Read is being denied. Likely Conditional Access or tenant-level restrictions on this client app.' 'Check Entra ID > Sign-in logs for this account/app; look at the Conditional Access tab of the failing sign-in.'
            }
            default {
                Write-Result FAIL 'Token' ('GET /me failed: {0}' -f $f.Text)
            }
        }
        if ($hint) { Write-Result INFO 'Token' ('Decoded: {0}' -f $hint) }
    }

    return $ctx
}

#endregion

#region Layer 4: Permission probes (403 layer) ------------------------------

function Test-PermissionProbes {
    param($Context)
    Write-Section 'Layer 4: Permission probes (403 layer)'
    Write-Line 'Each probe is a read-only GET. "ScopeInToken" = a satisfying scope is present in the session.' 'DarkGray'

    # SatisfiedBy lists every delegated scope that allows the call, least
    # privileged first; Suggest is the scope to request if it fails.
    $probes = @(
        @{ Name = 'Own profile';      Uri = '/v1.0/me';                      SatisfiedBy = @('User.Read', 'User.ReadWrite', 'User.Read.All', 'User.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All'); Suggest = 'User.Read' }
        @{ Name = 'Own group memberships'; Uri = '/v1.0/me/memberOf?$top=1'; SatisfiedBy = @('User.Read', 'Directory.Read.All', 'Directory.ReadWrite.All'); Suggest = 'User.Read' }
        @{ Name = 'List users';       Uri = '/v1.0/users?$top=1';            SatisfiedBy = @('User.ReadBasic.All', 'User.Read.All', 'User.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All'); Suggest = 'User.Read.All' }
        @{ Name = 'List groups';      Uri = '/v1.0/groups?$top=1';           SatisfiedBy = @('GroupMember.Read.All', 'Group.Read.All', 'Group.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All'); Suggest = 'Group.Read.All' }
        @{ Name = 'Own mailbox';      Uri = '/v1.0/me/messages?$top=1';      SatisfiedBy = @('Mail.Read', 'Mail.ReadWrite'); Suggest = 'Mail.Read' }
        @{ Name = 'Organization info'; Uri = '/v1.0/organization';           SatisfiedBy = @('User.Read', 'Organization.Read.All', 'Directory.Read.All'); Suggest = 'Organization.Read.All' }
        @{ Name = 'Directory roles';  Uri = '/v1.0/directoryRoles';          SatisfiedBy = @('RoleManagement.Read.Directory', 'Directory.Read.All', 'Directory.ReadWrite.All'); Suggest = 'RoleManagement.Read.Directory' }
        @{ Name = 'App registrations'; Uri = '/v1.0/applications?$top=1';    SatisfiedBy = @('Application.Read.All', 'Application.ReadWrite.All'); Suggest = 'Application.Read.All' }
        @{ Name = 'Sign-in logs';     Uri = '/v1.0/auditLogs/signIns?$top=1'; SatisfiedBy = @('AuditLog.Read.All'); Suggest = 'AuditLog.Read.All' }
    )

    $tokenScopes = @()
    if ($Context -and $Context.Scopes) { $tokenScopes = @($Context.Scopes) }

    $rows = New-Object System.Collections.ArrayList
    foreach ($p in $probes) {
        $satisfying = @($p.SatisfiedBy | Where-Object { $tokenScopes -contains $_ })
        $inToken = 'No'
        if ($satisfying.Count -gt 0) { $inToken = $satisfying[0] }

        $status = ''
        $note = ''
        try {
            Invoke-MgGraphRequest -Method GET -Uri $p.Uri -ErrorAction Stop | Out-Null
            $status = 'OK'
        }
        catch {
            $f = Get-FailureKind $_
            switch ($f.Kind) {
                'Forbidden' {
                    $status = '403'
                    if ($satisfying.Count -gt 0) {
                        $note = 'Scope is in the token but Graph still denied it - likely missing consent for the scope, or the resource also requires an Entra admin role.'
                    }
                    else {
                        $note = ('Request a scope: {0}' -f $p.Suggest)
                        if (-not ($script:MissingScopes -contains $p.Suggest)) { [void]$script:MissingScopes.Add($p.Suggest) }
                    }
                }
                'Unauthorized' { $status = '401'; $note = 'Token rejected - see Layer 3.' }
                'NotFound'     { $status = '404'; $note = 'Resource not found (often fine, e.g. no mailbox licence).' }
                default        { $status = 'ERR'; $note = $f.Text }
            }
            $hint = Get-GraphErrorHint $f.Text
            if ($hint -and $status -ne '403') { $note = ('{0} {1}' -f $note, $hint).Trim() }
        }
        [void]$rows.Add([pscustomobject]@{
                Probe = $p.Name; Result = $status; ScopeInToken = $inToken; LeastPrivScope = $p.Suggest; Note = $note
            })
    }

    $table = $rows | Format-Table -AutoSize -Wrap | Out-String
    foreach ($l in ($table -split "`r?`n")) { if ($l.Trim()) { Write-Line $l } }

    $denied = @($rows | Where-Object { $_.Result -eq '403' })
    $okCount = @($rows | Where-Object { $_.Result -eq 'OK' }).Count
    if ($denied.Count -eq 0) {
        Write-Result PASS 'Probes' ('{0}/{1} probes succeeded, no 403s.' -f $okCount, $rows.Count)
    }
    else {
        Write-Result FAIL 'Probes' ('{0} probe(s) denied with 403: {1}' -f $denied.Count, (($denied | Select-Object -ExpandProperty Probe) -join ', '))
    }
}

#endregion

#region Layer 5: Targeted lookup --------------------------------------------

function Test-TargetedCall {
    param($Context)
    if (-not $Cmdlet -and -not $Uri) { return }
    Write-Section 'Layer 5: Targeted permission lookup'

    if (-not (Get-Command Find-MgGraphCommand -ErrorAction SilentlyContinue)) {
        Write-Result WARN 'Targeted' 'Find-MgGraphCommand is unavailable; cannot map the call to permissions.' 'Update-Module Microsoft.Graph.Authentication'
        return
    }

    $found = $null
    try {
        if ($Cmdlet) {
            $found = @(Find-MgGraphCommand -Command $Cmdlet -ErrorAction Stop)
            Write-Result INFO 'Targeted' ('Cmdlet {0} maps to: {1}' -f $Cmdlet, (($found | ForEach-Object { '{0} {1}' -f $_.Method, $_.URI } | Select-Object -Unique) -join '; '))
        }
        else {
            $found = @(Find-MgGraphCommand -Uri $Uri -Method $Method -ApiVersion 'v1.0' -ErrorAction Stop)
            Write-Result INFO 'Targeted' ('{0} {1} maps to cmdlet(s): {2}' -f $Method, $Uri, (($found | Select-Object -ExpandProperty Command -Unique) -join ', '))
        }
    }
    catch {
        Write-Result WARN 'Targeted' ('Lookup failed: {0}' -f $_.Exception.Message) 'Check the cmdlet name / URI. For beta endpoints add the URI without version prefix and ensure the matching module is installed.'
        return
    }

    $perms = @($found | ForEach-Object { $_.Permissions } | Where-Object { $_ } | Sort-Object Name -Unique)
    if ($perms.Count -eq 0) {
        Write-Result WARN 'Targeted' 'No permissions are documented for this call (some endpoints are open or metadata is incomplete).'
        return
    }

    $tokenScopes = @()
    if ($Context -and $Context.Scopes) { $tokenScopes = @($Context.Scopes) }
    $have = @($perms | Where-Object { $tokenScopes -contains $_.Name })
    $missing = @($perms | Where-Object { $tokenScopes -notcontains $_.Name })

    Write-Result INFO 'Targeted' ('Accepted permissions: {0}' -f (($perms | ForEach-Object {
                    $flag = ''
                    if ($_.IsAdmin) { $flag = ' (admin consent)' }
                    '{0}{1}' -f $_.Name, $flag
                }) -join ', '))

    if ($have.Count -gt 0) {
        Write-Result PASS 'Targeted' ('Your token already contains a satisfying scope: {0}' -f (($have | Select-Object -ExpandProperty Name) -join ', '))
        Write-Result INFO 'Targeted' 'If the call still fails with 403, the remaining causes are: consent never granted for that scope, an Entra admin role is also required (e.g. reading other users'' data), or Conditional Access.'
    }
    else {
        $cheapest = $missing[0].Name
        if (-not ($script:MissingScopes -contains $cheapest)) { [void]$script:MissingScopes.Add($cheapest) }
        Write-Result FAIL 'Targeted' 'None of the accepted scopes are present in your token.' ('Reconnect with one of them, e.g.: Connect-MgGraph -Scopes "{0}"' -f $cheapest)
    }
}

#endregion

#region Layer 6: Tenant consent (best effort) -------------------------------

function Test-ConsentGrants {
    param($Context)
    if (-not $Context) { return }
    Write-Section 'Layer 6: Tenant consent grants (best effort)'

    try {
        $spResp = Invoke-MgGraphRequest -Method GET -Uri ("/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,displayName" -f $Context.ClientId) -ErrorAction Stop
        $sp = $null
        if ($spResp.value) { $sp = $spResp.value | Select-Object -First 1 }
        if (-not $sp) {
            Write-Result WARN 'Consent' 'No service principal found for the client app in this tenant - the app has never been consented here.' 'An admin (or first consenting user) must consent; re-run Connect-MgGraph and complete the consent prompt.'
            return
        }
        $grantsResp = Invoke-MgGraphRequest -Method GET -Uri ("/v1.0/oauth2PermissionGrants?`$filter=clientId eq '{0}'" -f $sp.id) -ErrorAction Stop
        $grants = @()
        if ($grantsResp.value) { $grants = @($grantsResp.value) }
        if ($grants.Count -eq 0) {
            Write-Result WARN 'Consent' ('Service principal "{0}" exists but has no delegated OAuth2 grants recorded.' -f $sp.displayName) 'Scopes were never consented. Reconnect and accept the consent prompt, or have an admin grant consent in Entra ID > Enterprise applications > the app > Permissions.'
            return
        }
        foreach ($g in $grants) {
            $who = 'a single user'
            if ($g.consentType -eq 'AllPrincipals') { $who = 'ALL users (admin consent)' }
            $scopeList = ''
            if ($g.scope) { $scopeList = ($g.scope.Trim() -split '\s+' | Sort-Object) -join ', ' }
            Write-Result INFO 'Consent' ('Granted for {0}: {1}' -f $who, $scopeList)
        }
        Write-Result PASS 'Consent' 'Consent grants retrieved. If a scope you need is absent above, that is your 403: it was requested but never consented.'
    }
    catch {
        $f = Get-FailureKind $_
        Write-Result INFO 'Consent' ('Could not read consent grants ({0}). This check itself needs directory read permission - safe to ignore.' -f $f.Kind)
    }
}

#endregion

#region Main -----------------------------------------------------------------

if ($Cmdlet -and $Uri) {
    throw 'Use either -Cmdlet or -Uri, not both.'
}

Write-Line 'Microsoft Graph permission diagnostics (delegated / PS 5.1)' 'Cyan'
Write-Line ('Run at {0} on {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:COMPUTERNAME) 'DarkGray'

$ErrorActionPreference = 'Continue'

Test-Environment
Test-Connectivity
$ctx = Test-GraphContext
if ($ctx) {
    if (-not $SkipProbes) { Test-PermissionProbes -Context $ctx }
    Test-TargetedCall -Context $ctx
    Test-ConsentGrants -Context $ctx
}
else {
    Write-Line ''
    Write-Line 'Skipping layers 4-6: no Graph session. Connect-MgGraph first, then re-run.' 'Yellow'
}

# Summary --------------------------------------------------------------------
Write-Section 'Summary'
$fails = @($script:Results | Where-Object { $_.Level -eq 'FAIL' })
$warns = @($script:Results | Where-Object { $_.Level -eq 'WARN' })
if ($fails.Count -eq 0 -and $warns.Count -eq 0) {
    Write-Line 'All checks passed. If a specific call still fails, re-run with -Cmdlet <name> or -Uri <path> to analyse it.' 'Green'
}
foreach ($r in $fails) {
    Write-Line ('FAIL  {0}: {1}' -f $r.Area, $r.Message) 'Red'
    if ($r.Fix) { Write-Line ('      -> {0}' -f $r.Fix) 'DarkGray' }
}
foreach ($r in $warns) {
    Write-Line ('WARN  {0}: {1}' -f $r.Area, $r.Message) 'Yellow'
    if ($r.Fix) { Write-Line ('      -> {0}' -f $r.Fix) 'DarkGray' }
}

if ($script:MissingScopes.Count -gt 0) {
    $scopeArg = ($script:MissingScopes | Sort-Object -Unique) -join '", "'
    Write-Line ''
    Write-Line 'Suggested reconnect command to pick up the missing scopes:' 'Cyan'
    Write-Line ('  Disconnect-MgGraph; Connect-MgGraph -Scopes "{0}"' -f $scopeArg) 'White'
    Write-Line '  (Scopes needing admin consent will prompt for it or fail with AADSTS65001 until an admin grants them.)' 'DarkGray'
}

if ($ReportPath) {
    try {
        $script:ReportLines | Out-File -FilePath $ReportPath -Encoding UTF8
        Write-Line ('Report written to {0}' -f (Resolve-Path $ReportPath)) 'Cyan'
    }
    catch {
        Write-Line ('Could not write report: {0}' -f $_.Exception.Message) 'Red'
    }
}

#endregion
