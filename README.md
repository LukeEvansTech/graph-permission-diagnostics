# entraidgraphperms

Diagnostics for Microsoft Graph API permission errors (401/403) hit by the
Microsoft Graph PowerShell SDK with delegated sign-in on Windows PowerShell 5.1.

## Usage

Copy `Invoke-GraphPermissionDiagnostics.ps1` to the affected machine, then in
the **same PowerShell session** where your Graph calls fail:

```powershell
# Full diagnostic run
.\Invoke-GraphPermissionDiagnostics.ps1

# Diagnose one specific failing cmdlet
.\Invoke-GraphPermissionDiagnostics.ps1 -Cmdlet Get-MgGroupMember

# Diagnose a raw Graph URI, and save a shareable report
.\Invoke-GraphPermissionDiagnostics.ps1 -Uri '/auditLogs/signIns' -ReportPath .\graph-diag.txt

# Skip the live probe battery (layer 4)
.\Invoke-GraphPermissionDiagnostics.ps1 -SkipProbes
```

Run it *after* `Connect-MgGraph` so layers 3-6 can inspect the live session;
without a session it still validates environment and connectivity.

The script is read-only: it makes no changes to the tenant or the machine.
All remediation is printed as suggested commands for you to run yourself.

## What it checks

| Layer | Diagnoses |
|-------|-----------|
| 1 Environment | PS/.NET versions, TLS 1.2 (the classic PS 5.1 killer), proxy, mixed Graph module versions |
| 2 Connectivity | TCP 443 to `login.microsoftonline.com` and `graph.microsoft.com` |
| 3 Token (401) | `Get-MgContext` sanity, scopes in token, live `/me` smoke test, AADSTS code decoding |
| 4 Probes (403) | Battery of read-only Graph calls vs the scopes actually in your token |
| 5 Targeted | Required permissions for *your* failing cmdlet/URI vs current scopes |
| 6 Consent | Tenant OAuth2 grants for the client app (best effort) |

It ends with a summary and, when scopes are missing, a ready-made
`Connect-MgGraph -Scopes ...` reconnect line.

Design notes: `docs/superpowers/specs/2026-06-12-graph-permission-diagnostics-design.md`
