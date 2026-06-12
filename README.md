# Graph Permission Diagnostics

Pinpoints why Microsoft Graph calls fail with 401/403 from the Microsoft Graph
PowerShell SDK (delegated sign-in) on Windows PowerShell 5.1.

Read-only: every Graph call is a GET and nothing on the machine is changed.
The only file it writes is the optional `-ReportPath` report.

## How to run

**1. Copy** `Invoke-GraphPermissionDiagnostics.ps1` to the affected machine.

**2. Unblock it** (files copied from another machine get marked as
downloaded, and execution policy may refuse to run them):

```powershell
Unblock-File .\Invoke-GraphPermissionDiagnostics.ps1
```

If scripts are blocked entirely, allow them for just this session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

**3. Connect to Graph** the same way your failing workload does — same
account, same scopes, **same PowerShell window**:

```powershell
Connect-MgGraph -Scopes "User.Read"
```

**4. Run it:**

```powershell
.\Invoke-GraphPermissionDiagnostics.ps1
```

## Common variations

```powershell
# Diagnose the one cmdlet that keeps failing
.\Invoke-GraphPermissionDiagnostics.ps1 -Cmdlet Get-MgGroupMember

# Diagnose a raw Graph URI instead
.\Invoke-GraphPermissionDiagnostics.ps1 -Uri '/auditLogs/signIns'

# Save a shareable text report
.\Invoke-GraphPermissionDiagnostics.ps1 -ReportPath .\graph-diag.txt

# Environment/token checks only, skip the live probe battery
.\Invoke-GraphPermissionDiagnostics.ps1 -SkipProbes
```

No Graph session yet? It still runs — layers 1–2 (environment, connectivity)
work standalone and it tells you how to connect for the rest.

## Reading the output

- **Green PASS** — that layer is fine, look further down.
- **Yellow WARN** — suspicious but not fatal (e.g. mixed module versions).
- **Red FAIL** — a found problem; each one prints a `fix:` line with the
  exact command or portal location to remediate.
- The **Summary** at the end repeats every FAIL/WARN and, if scopes were
  missing, gives you a ready-made line like:

  ```powershell
  Disconnect-MgGraph; Connect-MgGraph -Scopes "Group.Read.All", "User.Read.All"
  ```

Rule of thumb: 401s are fixed in layers 1–3 (TLS, clock, stale token);
403s are fixed in layers 4–6 (missing scope, missing consent, or the user
also needs an Entra admin role).

## Requirements

- Windows PowerShell 5.1 (works under PowerShell 7 too)
- `Microsoft.Graph.Authentication` module (the script tells you if it's
  missing or version-mismatched)
- No admin rights needed

Design notes: `docs/superpowers/specs/2026-06-12-graph-permission-diagnostics-design.md`
