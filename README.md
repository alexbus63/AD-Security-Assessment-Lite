# Active Directory Security Assessment Lite

Lightweight PowerShell-based Active Directory security assessment toolkit for rapid AD posture reviews, privilege exposure checks, stale object discovery, LAPS visibility validation, and executive-friendly reporting.

> Community edition. Designed for read-only assessments and safe GitHub publishing.

## Why This Exists

Most AD scripts dump raw data. This project focuses on practical security signals, simple risk scoring, and readable output that helps administrators prioritize remediation.

## Features

| Capability | Status |
|---|---:|
| Forest and domain inventory | Included |
| FSMO role discovery | Included |
| Domain password policy review | Included |
| Stale user discovery | Included |
| Stale computer discovery | Included |
| Privileged group membership review | Included |
| adminCount exposure check | Included |
| AdminSDHolder protected object assessment | Included |
| LAPS visibility check | Included |
| LDAP signing registry check | Included |
| Basic delegation discovery | Included |
| CSV output | Included |
| JSON output | Included |
| HTML summary report | Included |
| AD CS advanced analysis | Pro / private edition |
| Tiering model analysis | Pro / private edition |
| ServiceNow remediation export | Pro / private edition |

## Requirements

- Windows PowerShell 5.1+
- RSAT Active Directory PowerShell module
- Domain-joined workstation or server
- Standard domain user permissions for most checks

Install RSAT AD module if needed:

```powershell
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online
```

## Usage

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\Invoke-ADSecurityAssessmentLite.ps1 `
    -OutputPath C:\Temp\ADSecurityAssessmentLite `
    -GenerateHTML `
    -GenerateJSON `
    -GenerateCSV
```

## Example Output

```text
[+] Starting Active Directory Security Assessment Lite
[+] Collecting forest and domain inventory
[+] Reviewing privileged groups
[+] Checking stale users and computers
[+] Checking password policy
[+] Checking LAPS visibility
[+] Checking LDAP signing on domain controllers
[+] Checking AdminSDHolder/adminCount protected objects
[+] Generating reports
[+] Assessment complete
```

## Output Files

| File | Description |
|---|---|
| AD_Assessment_Summary.html | Executive-friendly summary report |
| AD_Assessment_Results.json | Structured evidence output |
| AD_Assessment_Findings.csv | Findings table |
| AD_Assessment.log | Runtime log |

## Safety Notes

This tool is designed for read-only review. It does not modify AD objects, GPOs, policies, accounts, groups, or registry settings.

Before publishing your own fork, remove all real company names, domains, usernames, hostnames, IP addresses, and findings.

## GitHub Topics

`powershell` `active-directory` `cybersecurity` `windows-server` `blue-team` `ad-security` `identity-security` `laps`

## License

MIT License.


## Risk Scoring

The Lite edition uses a simple, transparent scoring model:

| Severity | Points |
|---|---:|
| Critical | 25 |
| High | 15 |
| Medium | 8 |
| Low | 3 |
| Informational | 0 |

The final Risk Score is the sum of finding points, capped at 100.

| Score | Rating |
|---:|---|
| 90-100 | Critical |
| 70-89 | High |
| 40-69 | Medium |
| 20-39 | Low |
| 0-19 | Healthy |

A score of `100 / 100` means the environment reached the maximum risk cap based on multiple findings. It does not mean every possible AD issue exists.


## Evidence / Found Values

The report shows the actual found values, not only summary counts. The HTML report includes detailed evidence tables for:

- Domain controllers
- Stale users
- Stale computers
- adminCount users
- AdminSDHolder protected objects
- LDAP signing values per domain controller
- Privileged group members
- Password policy values
- LAPS schema visibility values

When `-GenerateCSV` or `-GenerateHTML` is used, full evidence CSV files are also exported under:

```text
Output\Evidence\
```

Example evidence files:

```text
DomainControllers.csv
StaleUsers.csv
StaleComputers.csv
AdminCountUsers.csv
AdminSDHolderProtectedObjects.csv
AdminSDHolderUsers.csv
AdminSDHolderGroups.csv
AdminSDHolderComputers.csv
LDAPSigning.csv
PrivilegedGroupMembers.csv
PasswordPolicy.csv
LAPSVisibility.csv
```
