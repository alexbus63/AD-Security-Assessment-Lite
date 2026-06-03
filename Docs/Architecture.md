# Architecture

Active Directory Security Assessment Lite uses a simple modular PowerShell layout.

## Design Goals

- Read-only collection
- Minimal permissions
- Clean module boundaries
- Structured output
- Executive-friendly reporting
- Safe public GitHub release

## Components

| Component | Purpose |
|---|---|
| Invoke-ADSecurityAssessmentLite.ps1 | Main entry point |
| AD.Inventory.psm1 | Forest/domain/DC inventory |
| AD.StaleObjects.psm1 | Stale user and computer checks |
| AD.PrivilegedAccess.psm1 | Privileged groups and adminCount checks |
| AD.PasswordPolicy.psm1 | Default password policy review |
| AD.LAPS.psm1 | LAPS schema visibility checks |
| AD.Reporting.psm1 | Findings and report generation |
