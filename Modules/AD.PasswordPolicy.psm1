function Get-ADLitePasswordPolicy {
    [CmdletBinding()]
    param()

    $policy = Get-ADDefaultDomainPasswordPolicy

    [pscustomobject]@{
        ComplexityEnabled           = $policy.ComplexityEnabled
        MinPasswordLength           = $policy.MinPasswordLength
        MaxPasswordAgeDays          = $policy.MaxPasswordAge.TotalDays
        MinPasswordAgeDays          = $policy.MinPasswordAge.TotalDays
        PasswordHistoryCount        = $policy.PasswordHistoryCount
        ReversibleEncryptionEnabled = $policy.ReversibleEncryptionEnabled
        LockoutThreshold            = $policy.LockoutThreshold
        LockoutDurationMinutes      = $policy.LockoutDuration.TotalMinutes
        LockoutObservationMinutes   = $policy.LockoutObservationWindow.TotalMinutes
    }
}

Export-ModuleMember -Function Get-ADLitePasswordPolicy
