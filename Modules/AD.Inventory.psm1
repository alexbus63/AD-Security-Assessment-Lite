function Get-ADLiteInventory {
    [CmdletBinding()]
    param()

    $forest = Get-ADForest
    $domain = Get-ADDomain

    [pscustomobject]@{
        ForestName             = $forest.Name
        ForestMode             = $forest.ForestMode
        DomainName             = $domain.DNSRoot
        DomainMode             = $domain.DomainMode
        NetBIOSName            = $domain.NetBIOSName
        PDCEmulator            = $domain.PDCEmulator
        RIDMaster              = $domain.RIDMaster
        InfrastructureMaster   = $domain.InfrastructureMaster
        SchemaMaster           = $forest.SchemaMaster
        DomainNamingMaster     = $forest.DomainNamingMaster
        DomainControllers      = @(Get-ADDomainController -Filter * | Select-Object HostName,Site,OperatingSystem,IPv4Address)
    }
}

Export-ModuleMember -Function Get-ADLiteInventory
