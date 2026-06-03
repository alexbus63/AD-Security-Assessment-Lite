function Get-ADLiteStaleObjects {
    [CmdletBinding()]
    param(
        [int]$StaleDays = 90
    )

    $cutoff = (Get-Date).AddDays(-$StaleDays)

    $staleUsers = Get-ADUser -Filter "Enabled -eq 'True' -and LastLogonDate -lt '$cutoff'" -Properties LastLogonDate,Enabled |
        Select-Object Name,SamAccountName,Enabled,LastLogonDate,DistinguishedName

    $staleComputers = Get-ADComputer -Filter "Enabled -eq 'True' -and LastLogonDate -lt '$cutoff'" -Properties LastLogonDate,OperatingSystem,Enabled |
        Select-Object Name,DNSHostName,OperatingSystem,Enabled,LastLogonDate,DistinguishedName

    [pscustomobject]@{
        StaleDays      = $StaleDays
        CutoffDate     = $cutoff
        StaleUsers     = @($staleUsers)
        StaleComputers = @($staleComputers)
    }
}

Export-ModuleMember -Function Get-ADLiteStaleObjects
