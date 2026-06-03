function Get-ADLiteAdminSDHolderAssessment {
    [CmdletBinding()]
    param()

    $users = @(Get-ADUser -LDAPFilter '(adminCount=1)' -Properties adminCount,Enabled,LastLogonDate,whenChanged,whenCreated | 
        Select-Object Name,SamAccountName,Enabled,LastLogonDate,whenChanged,whenCreated,DistinguishedName)

    $groups = @(Get-ADGroup -LDAPFilter '(adminCount=1)' -Properties adminCount,whenChanged,whenCreated | 
        Select-Object Name,SamAccountName,GroupCategory,GroupScope,whenChanged,whenCreated,DistinguishedName)

    $computers = @(Get-ADComputer -LDAPFilter '(adminCount=1)' -Properties adminCount,Enabled,LastLogonDate,OperatingSystem,whenChanged,whenCreated | 
        Select-Object Name,DNSHostName,OperatingSystem,Enabled,LastLogonDate,whenChanged,whenCreated,DistinguishedName)

    $allProtectedObjects = @()
    $allProtectedObjects += foreach ($user in $users) {
        [pscustomobject]@{
            ObjectType        = 'User'
            Name              = $user.Name
            SamAccountName    = $user.SamAccountName
            Enabled           = $user.Enabled
            LastLogonDate     = $user.LastLogonDate
            OperatingSystem   = $null
            WhenChanged       = $user.whenChanged
            WhenCreated       = $user.whenCreated
            DistinguishedName = $user.DistinguishedName
        }
    }
    $allProtectedObjects += foreach ($group in $groups) {
        [pscustomobject]@{
            ObjectType        = 'Group'
            Name              = $group.Name
            SamAccountName    = $group.SamAccountName
            Enabled           = $null
            LastLogonDate     = $null
            OperatingSystem   = $null
            WhenChanged       = $group.whenChanged
            WhenCreated       = $group.whenCreated
            DistinguishedName = $group.DistinguishedName
        }
    }
    $allProtectedObjects += foreach ($computer in $computers) {
        [pscustomobject]@{
            ObjectType        = 'Computer'
            Name              = $computer.Name
            SamAccountName    = $computer.DNSHostName
            Enabled           = $computer.Enabled
            LastLogonDate     = $computer.LastLogonDate
            OperatingSystem   = $computer.OperatingSystem
            WhenChanged       = $computer.whenChanged
            WhenCreated       = $computer.whenCreated
            DistinguishedName = $computer.DistinguishedName
        }
    }

    [pscustomobject]@{
        ProtectedUserCount     = $users.Count
        ProtectedGroupCount    = $groups.Count
        ProtectedComputerCount = $computers.Count
        ProtectedObjectCount   = @($allProtectedObjects).Count
        ProtectedUsers         = @($users)
        ProtectedGroups        = @($groups)
        ProtectedComputers     = @($computers)
        ProtectedObjects       = @($allProtectedObjects)
        Note                   = 'Objects with adminCount=1 are protected by AdminSDHolder or have privileged history. Validate whether each object still requires protection.'
    }
}

Export-ModuleMember -Function Get-ADLiteAdminSDHolderAssessment
