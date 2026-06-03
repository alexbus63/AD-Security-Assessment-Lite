# Findings Reference

## Stale Enabled User Accounts

Enabled accounts with no recent logon activity increase identity risk and should be reviewed.

## Stale Enabled Computer Accounts

Old computer objects may represent retired assets, unmanaged systems, or stale attack paths.

## adminCount=1 Users

Users with adminCount=1 may be currently or historically privileged. Review group membership and AdminSDHolder impact.

## Weak Password Policy

Weak default domain password settings may increase credential compromise risk.

## LAPS Visibility Gap

Missing LAPS indicators should trigger validation of local administrator password management strategy.


## Evidence / Found Values

Each finding includes:

- `FoundCount` — number of matching objects or value found
- `Evidence` — short evidence summary
- `EvidenceFile` — matching CSV export under the Evidence folder

The HTML report also renders full evidence tables so reviewers can see the actual objects behind each finding.


## LDAP Signing

Checks each domain controller remote registry value:

```text
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity
```

| Value | Meaning | Severity |
|---:|---|---|
| 0 | Signing not required | Critical |
| 1 | Negotiate signing | Medium |
| 2 | Require signing | Pass |

Evidence file: `Evidence\LDAPSigning.csv`

## AdminSDHolder / adminCount

Collects users, groups, and computers with `adminCount=1`. These objects are protected by AdminSDHolder or have privileged history.

Severity is based on protected object count:

| Count | Severity |
|---:|---|
| 1-10 | Medium |
| 11-25 | High |
| 26+ | Critical |

Evidence files:

- `Evidence\AdminSDHolderProtectedObjects.csv`
- `Evidence\AdminSDHolderUsers.csv`
- `Evidence\AdminSDHolderGroups.csv`
- `Evidence\AdminSDHolderComputers.csv`
