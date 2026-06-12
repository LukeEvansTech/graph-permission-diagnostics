# Graph Permission Diagnostics — Design

**Date:** 2026-06-12
**Status:** Approved

## Problem

A Windows PowerShell 5.1 machine using the Microsoft Graph PowerShell SDK with
delegated (signed-in user) authentication is hitting both 401 token errors
(AADSTS codes, `InvalidAuthenticationToken`) and 403 permission errors
(`Authorization_RequestDenied`). The operator needs a single script that
pinpoints which layer is failing and says how to fix it.

## Deliverable

`Invoke-GraphPermissionDiagnostics.ps1` — a single self-contained, read-only,
PS 5.1-compatible script. Copy it to the affected machine and run it. No
dependencies beyond the Microsoft.Graph SDK it is diagnosing; every check
degrades gracefully if its own prerequisites are missing.

## Layers (run in order; each explains failures in the next)

1. **Environment** — PS version; .NET Framework ≥ 4.7.2 (registry `Release`
   value); TLS 1.2 in `[Net.ServicePointManager]::SecurityProtocol` plus
   `SchUseStrongCrypto`/`SystemDefaultTlsVersions` registry hints; WinHTTP/
   WebRequest proxy; installed `Microsoft.Graph.*` module inventory with
   mixed-version detection (mismatched sub-module versions vs
   Microsoft.Graph.Authentication cause opaque auth failures).
2. **Connectivity** — TCP 443 reachability to `login.microsoftonline.com` and
   `graph.microsoft.com` via `TcpClient` with timeout.
3. **Token/context (401 layer)** — `Get-MgContext`: auth type (expects
   Delegated), account, tenant, client app, granted scopes. A built-in AADSTS
   decoder translates common codes (50076 MFA, 65001 consent, 53003
   Conditional Access, 700082 expired refresh token, 7000218 client assertion,
   etc.) into plain-English causes wherever an exception surfaces one.
4. **Permission probes (403 layer)** — battery of representative live GET
   calls (`/me`, `/users`, `/groups`, `/me/messages`, `/directoryRoles`, …),
   each annotated with its least-privileged delegated scope. Results table
   shows HTTP outcome, whether the scope was present in the token, and the
   exact `Connect-MgGraph -Scopes ...` line to remediate.
5. **Targeted mode** — `-Cmdlet <name>` or `-Uri <path> [-Method GET]`
   parameters use `Find-MgGraphCommand` to look up required permissions for a
   specific failing call and diff them against current context scopes.
6. **Tenant consent check** — best-effort read of the client app's service
   principal and its `oauth2PermissionGrants` to distinguish "scope never
   requested" from "admin never consented". Wrapped in try/catch since it
   needs directory read permission itself.

Output: colourised PASS/WARN/FAIL console report, summary of failures with
remediation steps, optional `-ReportPath` plain-text report for sharing.

## Constraints

- Strict PS 5.1 syntax (no ternary, no `??`, no `&&`/`||` pipeline chains).
- Read-only against the tenant; no admin rights required on the box.
- One failed layer never aborts the run — it becomes a FAIL line with advice.

## Testing

Authoring happens on macOS: syntax validated with the PowerShell parser and
PSScriptAnalyzer `PSUseCompatibleSyntax` targeting 5.1. Live execution is on
the target Windows machine.
