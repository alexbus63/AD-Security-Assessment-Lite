function Get-ADLiteLAPSVisibility {
    [CmdletBinding()]
    param()

    $schemaSignals = [ordered]@{
        LegacyLAPSAttributeFound = $false
        WindowsLAPSAttributeFound = $false
    }

    try {
        $schema = (Get-ADRootDSE).schemaNamingContext
        $legacy = Get-ADObject -SearchBase $schema -LDAPFilter "(lDAPDisplayName=ms-Mcs-AdmPwd)" -ErrorAction SilentlyContinue
        $windows = Get-ADObject -SearchBase $schema -LDAPFilter "(lDAPDisplayName=msLAPS-Password)" -ErrorAction SilentlyContinue

        $schemaSignals.LegacyLAPSAttributeFound = [bool]$legacy
        $schemaSignals.WindowsLAPSAttributeFound = [bool]$windows
    }
    catch {
        $schemaSignals.SchemaCheckError = $_.Exception.Message
    }

    [pscustomobject]@{
        LegacyLAPSAttributeFound  = $schemaSignals.LegacyLAPSAttributeFound
        WindowsLAPSAttributeFound = $schemaSignals.WindowsLAPSAttributeFound
        Note = "Schema visibility only. This does not confirm policy health on every endpoint."
    }
}

Export-ModuleMember -Function Get-ADLiteLAPSVisibility
