function Get-ADLitePrivilegedAccess {
    [CmdletBinding()]
    param()

    $groups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Server Operators",
        "Backup Operators"
    )

    $groupResults = foreach ($group in $groups) {
        try {
            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop |
                Select-Object Name,SamAccountName,ObjectClass,DistinguishedName

            [pscustomobject]@{
                GroupName = $group
                MemberCount = @($members).Count
                Members = @($members)
            }
        }
        catch {
            [pscustomobject]@{
                GroupName = $group
                MemberCount = 0
                Members = @()
                Error = $_.Exception.Message
            }
        }
    }

    $adminCountUsers = Get-ADUser -LDAPFilter "(adminCount=1)" -Properties adminCount,Enabled,LastLogonDate |
        Select-Object Name,SamAccountName,Enabled,LastLogonDate,DistinguishedName

    [pscustomobject]@{
        PrivilegedGroups = @($groupResults)
        AdminCountUsers  = @($adminCountUsers)
    }
}

Export-ModuleMember -Function Get-ADLitePrivilegedAccess
