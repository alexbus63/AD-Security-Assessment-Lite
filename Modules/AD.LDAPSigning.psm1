function Get-ADLiteLDAPSigning {
    [CmdletBinding()]
    param()

    $domainControllers = @(Get-ADDomainController -Filter *)

    $results = foreach ($dc in $domainControllers) {
        $integrityValue = $null
        $status = 'Unknown'
        $findingState = 'Unknown'
        $errorMessage = $null

        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.HostName)
            $key = $reg.OpenSubKey('SYSTEM\CurrentControlSet\Services\NTDS\Parameters')

            if ($null -ne $key) {
                $rawValue = $key.GetValue('LDAPServerIntegrity', $null)
                if ($null -ne $rawValue) {
                    $integrityValue = [int]$rawValue
                }
            }

            switch ($integrityValue) {
                0       { $status = 'Not required'; $findingState = 'Fail' }
                1       { $status = 'Negotiate signing'; $findingState = 'Warning' }
                2       { $status = 'Require signing'; $findingState = 'Pass' }
                $null   { $status = 'Not configured or unreadable'; $findingState = 'Unknown' }
                default { $status = "Unexpected value: $integrityValue"; $findingState = 'Unknown' }
            }
        }
        catch {
            $status = 'Unable to read remote registry'
            $findingState = 'Unknown'
            $errorMessage = $_.Exception.Message
        }

        [pscustomobject]@{
            DomainController    = $dc.HostName
            Site                = $dc.Site
            OperatingSystem     = $dc.OperatingSystem
            IPv4Address         = $dc.IPv4Address
            LDAPServerIntegrity = $integrityValue
            Status              = $status
            FindingState        = $findingState
            Error               = $errorMessage
        }
    }

    $failed = @($results | Where-Object FindingState -eq 'Fail')
    $warnings = @($results | Where-Object FindingState -eq 'Warning')
    $unknown = @($results | Where-Object FindingState -eq 'Unknown')
    $passed = @($results | Where-Object FindingState -eq 'Pass')

    [pscustomobject]@{
        DomainControllerCount = @($results).Count
        RequireSigningCount   = $passed.Count
        NegotiateCount        = $warnings.Count
        NotRequiredCount      = $failed.Count
        UnknownCount          = $unknown.Count
        DomainControllers     = @($results)
        Note                  = 'Reads LDAPServerIntegrity from each DC remote registry. Value 2 means require LDAP signing.'
    }
}

Export-ModuleMember -Function Get-ADLiteLDAPSigning
