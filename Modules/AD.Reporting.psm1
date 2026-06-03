function New-ADLiteFindingSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$AssessmentResults
    )

    $findings = New-Object System.Collections.Generic.List[object]

    function Get-SafeCount {
        param([object]$Value)
        if ($null -eq $Value) { return 0 }
        return @($Value).Count
    }

    function Get-PreviewValue {
        param(
            [object]$Value,
            [string]$PropertyName = 'Name',
            [int]$MaxItems = 10
        )

        if ($null -eq $Value) { return '' }

        $items = @($Value) | Select-Object -First $MaxItems
        $names = foreach ($item in $items) {
            if ($null -ne $item.PSObject.Properties[$PropertyName]) { [string]$item.$PropertyName }
            elseif ($null -ne $item.PSObject.Properties['SamAccountName']) { [string]$item.SamAccountName }
            elseif ($null -ne $item.PSObject.Properties['DNSHostName']) { [string]$item.DNSHostName }
            elseif ($null -ne $item.PSObject.Properties['DomainController']) { [string]$item.DomainController }
            elseif ($null -ne $item.PSObject.Properties['Name']) { [string]$item.Name }
            else { [string]$item }
        }

        return ($names -join '; ')
    }

    function Add-Finding {
        param(
            [Parameter(Mandatory)] [string]$Title,
            [Parameter(Mandatory)] [ValidateSet('Critical','High','Medium','Low','Informational')] [string]$Severity,
            [Parameter(Mandatory)] [string]$Category,
            [Parameter(Mandatory)] [int]$FoundCount,
            [Parameter(Mandatory)] [string]$Evidence,
            [Parameter(Mandatory)] [string]$Description,
            [Parameter(Mandatory)] [string]$Recommendation,
            [string]$EvidenceFile = ''
        )

        $riskPoints = switch ($Severity) {
            'Critical'      { 25 }
            'High'          { 15 }
            'Medium'        { 8 }
            'Low'           { 3 }
            'Informational' { 0 }
        }

        [void]$findings.Add([pscustomobject]@{
            Title          = $Title
            Severity       = $Severity
            RiskPoints     = $riskPoints
            Category       = $Category
            FoundCount     = $FoundCount
            Evidence       = $Evidence
            EvidenceFile   = $EvidenceFile
            Description    = $Description
            Recommendation = $Recommendation
        })
    }

    $staleUserCount = Get-SafeCount $AssessmentResults.StaleObjects.StaleUsers
    if ($staleUserCount -gt 0) {
        $preview = Get-PreviewValue -Value $AssessmentResults.StaleObjects.StaleUsers -PropertyName 'SamAccountName'
        Add-Finding -Title 'Stale enabled user accounts found' -Severity 'Medium' -Category 'Identity Hygiene' -FoundCount $staleUserCount -Evidence "Found $staleUserCount enabled stale user account(s). Sample: $preview" -EvidenceFile 'Evidence\StaleUsers.csv' -Description "Enabled user accounts with no logon activity older than $($AssessmentResults.StaleObjects.StaleDays) days were found." -Recommendation 'Review, disable, or remove stale accounts after business validation.'
    }

    $staleComputerCount = Get-SafeCount $AssessmentResults.StaleObjects.StaleComputers
    if ($staleComputerCount -gt 0) {
        $preview = Get-PreviewValue -Value $AssessmentResults.StaleObjects.StaleComputers -PropertyName 'DNSHostName'
        Add-Finding -Title 'Stale enabled computer accounts found' -Severity 'Medium' -Category 'Endpoint Hygiene' -FoundCount $staleComputerCount -Evidence "Found $staleComputerCount enabled stale computer account(s). Sample: $preview" -EvidenceFile 'Evidence\StaleComputers.csv' -Description "Enabled computer accounts with no logon activity older than $($AssessmentResults.StaleObjects.StaleDays) days were found." -Recommendation 'Review stale computer objects and remove retired assets from Active Directory.'
    }

    $adminCountUserCount = Get-SafeCount $AssessmentResults.PrivilegedAccess.AdminCountUsers
    if ($adminCountUserCount -gt 0) {
        $preview = Get-PreviewValue -Value $AssessmentResults.PrivilegedAccess.AdminCountUsers -PropertyName 'SamAccountName'
        Add-Finding -Title 'adminCount=1 users detected' -Severity 'High' -Category 'Privileged Access' -FoundCount $adminCountUserCount -Evidence "Found $adminCountUserCount adminCount=1 user account(s). Sample: $preview" -EvidenceFile 'Evidence\AdminCountUsers.csv' -Description 'User accounts with adminCount=1 were detected.' -Recommendation 'Review privileged history, remove unnecessary access, and reset adminCount when appropriate.'
    }

    if ($null -ne $AssessmentResults.AdminSDHolder) {
        $protectedObjectCount = [int]$AssessmentResults.AdminSDHolder.ProtectedObjectCount
        if ($protectedObjectCount -gt 0) {
            $severity = if ($protectedObjectCount -gt 25) { 'Critical' } elseif ($protectedObjectCount -gt 10) { 'High' } else { 'Medium' }
            $preview = Get-PreviewValue -Value $AssessmentResults.AdminSDHolder.ProtectedObjects -PropertyName 'SamAccountName'
            Add-Finding -Title 'AdminSDHolder protected objects detected' -Severity $severity -Category 'Privileged Access' -FoundCount $protectedObjectCount -Evidence "Found $protectedObjectCount adminCount=1 protected object(s). Users=$($AssessmentResults.AdminSDHolder.ProtectedUserCount); Groups=$($AssessmentResults.AdminSDHolder.ProtectedGroupCount); Computers=$($AssessmentResults.AdminSDHolder.ProtectedComputerCount). Sample: $preview" -EvidenceFile 'Evidence\AdminSDHolderProtectedObjects.csv' -Description 'Objects with adminCount=1 are protected by AdminSDHolder or have privileged history. This can preserve elevated ACL protection after membership changes.' -Recommendation 'Validate whether each protected object still requires privileged protection. Remove unnecessary privileged membership and reset adminCount only after proper review.'
        }
    }

    $privilegedGroups = @($AssessmentResults.PrivilegedAccess.PrivilegedGroups)
    $memberSum = ($privilegedGroups | Measure-Object -Property MemberCount -Sum).Sum
    $privilegedMemberCount = if ($null -eq $memberSum) { 0 } else { [int]$memberSum }
    if ($privilegedMemberCount -gt 0) {
        Add-Finding -Title 'Privileged group members detected' -Severity 'Informational' -Category 'Privileged Access' -FoundCount $privilegedMemberCount -Evidence "Found $privilegedMemberCount total member assignment(s) across monitored privileged groups." -EvidenceFile 'Evidence\PrivilegedGroupMembers.csv' -Description 'Built-in privileged group membership was collected for review.' -Recommendation 'Validate each privileged group member and remove unnecessary standing access.'
    }

    if ($null -ne $AssessmentResults.LDAPSigning) {
        $notRequired = [int]$AssessmentResults.LDAPSigning.NotRequiredCount
        $negotiate = [int]$AssessmentResults.LDAPSigning.NegotiateCount
        $unknown = [int]$AssessmentResults.LDAPSigning.UnknownCount

        if ($notRequired -gt 0) {
            $badDcs = @($AssessmentResults.LDAPSigning.DomainControllers | Where-Object FindingState -eq 'Fail')
            $preview = Get-PreviewValue -Value $badDcs -PropertyName 'DomainController'
            Add-Finding -Title 'LDAP signing is not required on one or more domain controllers' -Severity 'Critical' -Category 'Domain Controller Security' -FoundCount $notRequired -Evidence "LDAPServerIntegrity=0 found on $notRequired domain controller(s). Sample: $preview" -EvidenceFile 'Evidence\LDAPSigning.csv' -Description 'Domain controllers that do not require LDAP signing may allow unsigned LDAP binds, increasing exposure to relay and downgrade scenarios.' -Recommendation 'Validate application compatibility, then configure domain controllers to require LDAP signing.'
        }
        elseif ($negotiate -gt 0) {
            $warnDcs = @($AssessmentResults.LDAPSigning.DomainControllers | Where-Object FindingState -eq 'Warning')
            $preview = Get-PreviewValue -Value $warnDcs -PropertyName 'DomainController'
            Add-Finding -Title 'LDAP signing is configured as negotiate on one or more domain controllers' -Severity 'Medium' -Category 'Domain Controller Security' -FoundCount $negotiate -Evidence "LDAPServerIntegrity=1 found on $negotiate domain controller(s). Sample: $preview" -EvidenceFile 'Evidence\LDAPSigning.csv' -Description 'LDAP signing is negotiated but not strictly required on one or more domain controllers.' -Recommendation 'Review client compatibility and move toward requiring LDAP signing on domain controllers.'
        }

        if ($unknown -gt 0) {
            $unknownDcs = @($AssessmentResults.LDAPSigning.DomainControllers | Where-Object FindingState -eq 'Unknown')
            $preview = Get-PreviewValue -Value $unknownDcs -PropertyName 'DomainController'
            Add-Finding -Title 'LDAP signing status could not be verified on one or more domain controllers' -Severity 'Low' -Category 'Domain Controller Security' -FoundCount $unknown -Evidence "Unable to verify LDAPServerIntegrity on $unknown domain controller(s). Sample: $preview" -EvidenceFile 'Evidence\LDAPSigning.csv' -Description 'The assessment could not read the LDAP signing registry value from one or more domain controllers.' -Recommendation 'Verify remote registry access, permissions, firewall rules, and manually confirm LDAP signing configuration.'
        }
    }

    if ($null -ne $AssessmentResults.PasswordPolicy -and -not [bool]$AssessmentResults.PasswordPolicy.ComplexityEnabled) {
        Add-Finding -Title 'Password complexity is disabled' -Severity 'High' -Category 'Password Policy' -FoundCount 1 -Evidence "ComplexityEnabled=$($AssessmentResults.PasswordPolicy.ComplexityEnabled)" -EvidenceFile 'Evidence\PasswordPolicy.csv' -Description 'The default domain password policy does not enforce complexity.' -Recommendation 'Enable password complexity or enforce stronger authentication controls.'
    }

    if ($null -ne $AssessmentResults.PasswordPolicy -and [int]$AssessmentResults.PasswordPolicy.MinPasswordLength -lt 12) {
        Add-Finding -Title 'Minimum password length below recommended baseline' -Severity 'Medium' -Category 'Password Policy' -FoundCount ([int]$AssessmentResults.PasswordPolicy.MinPasswordLength) -Evidence "MinPasswordLength=$($AssessmentResults.PasswordPolicy.MinPasswordLength); RecommendedBaseline=12" -EvidenceFile 'Evidence\PasswordPolicy.csv' -Description "Minimum password length is $($AssessmentResults.PasswordPolicy.MinPasswordLength), which is lower than the recommended baseline of 12." -Recommendation 'Increase minimum password length based on organizational policy and MFA coverage.'
    }

    if ($null -ne $AssessmentResults.LAPS -and -not [bool]$AssessmentResults.LAPS.LegacyLAPSAttributeFound -and -not [bool]$AssessmentResults.LAPS.WindowsLAPSAttributeFound) {
        Add-Finding -Title 'No LAPS schema indicators detected' -Severity 'Medium' -Category 'Local Administrator Password Management' -FoundCount 0 -Evidence "LegacyLAPSAttributeFound=$($AssessmentResults.LAPS.LegacyLAPSAttributeFound); WindowsLAPSAttributeFound=$($AssessmentResults.LAPS.WindowsLAPSAttributeFound)" -EvidenceFile 'Evidence\LAPSVisibility.csv' -Description 'No legacy or Windows LAPS schema attributes were visible from this context.' -Recommendation 'Validate whether LAPS is deployed through AD, Entra ID, or another local admin password management solution.'
    }

    return @($findings.ToArray())
}

function Get-ADLiteRiskSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]]$Findings
    )

    $score = 0
    if (@($Findings).Count -gt 0) {
        $sum = ($Findings | Measure-Object -Property RiskPoints -Sum).Sum
        if ($null -ne $sum) { $score = [int]$sum }
    }

    $score = [math]::Min(100, $score)

    $rating = switch ($score) {
        { $_ -ge 90 } { 'Critical'; break }
        { $_ -ge 70 } { 'High'; break }
        { $_ -ge 40 } { 'Medium'; break }
        { $_ -ge 20 } { 'Low'; break }
        default       { 'Healthy' }
    }

    return [pscustomobject]@{
        RiskScore        = $score
        RiskRating       = $rating
        CriticalFindings = @($Findings | Where-Object Severity -eq 'Critical').Count
        HighFindings     = @($Findings | Where-Object Severity -eq 'High').Count
        MediumFindings   = @($Findings | Where-Object Severity -eq 'Medium').Count
        LowFindings      = @($Findings | Where-Object Severity -eq 'Low').Count
    }
}

function Export-ADLiteEvidenceFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$AssessmentResults,
        [Parameter(Mandatory)] [string]$OutputPath
    )

    $evidencePath = Join-Path $OutputPath 'Evidence'
    if (-not (Test-Path $evidencePath)) {
        New-Item -Path $evidencePath -ItemType Directory -Force | Out-Null
    }

    if ($null -ne $AssessmentResults.Inventory.DomainControllers) {
        @($AssessmentResults.Inventory.DomainControllers) | Export-Csv -Path (Join-Path $evidencePath 'DomainControllers.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($null -ne $AssessmentResults.StaleObjects.StaleUsers) {
        @($AssessmentResults.StaleObjects.StaleUsers) | Export-Csv -Path (Join-Path $evidencePath 'StaleUsers.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($null -ne $AssessmentResults.StaleObjects.StaleComputers) {
        @($AssessmentResults.StaleObjects.StaleComputers) | Export-Csv -Path (Join-Path $evidencePath 'StaleComputers.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($null -ne $AssessmentResults.PrivilegedAccess.AdminCountUsers) {
        @($AssessmentResults.PrivilegedAccess.AdminCountUsers) | Export-Csv -Path (Join-Path $evidencePath 'AdminCountUsers.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($null -ne $AssessmentResults.AdminSDHolder.ProtectedObjects) {
        @($AssessmentResults.AdminSDHolder.ProtectedObjects) | Export-Csv -Path (Join-Path $evidencePath 'AdminSDHolderProtectedObjects.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($null -ne $AssessmentResults.AdminSDHolder.ProtectedUsers) {
        @($AssessmentResults.AdminSDHolder.ProtectedUsers) | Export-Csv -Path (Join-Path $evidencePath 'AdminSDHolderUsers.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($null -ne $AssessmentResults.AdminSDHolder.ProtectedGroups) {
        @($AssessmentResults.AdminSDHolder.ProtectedGroups) | Export-Csv -Path (Join-Path $evidencePath 'AdminSDHolderGroups.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($null -ne $AssessmentResults.AdminSDHolder.ProtectedComputers) {
        @($AssessmentResults.AdminSDHolder.ProtectedComputers) | Export-Csv -Path (Join-Path $evidencePath 'AdminSDHolderComputers.csv') -NoTypeInformation -Encoding UTF8
    }

    $memberRows = foreach ($group in @($AssessmentResults.PrivilegedAccess.PrivilegedGroups)) {
        foreach ($member in @($group.Members)) {
            [pscustomobject]@{
                GroupName         = $group.GroupName
                MemberName        = $member.Name
                SamAccountName    = $member.SamAccountName
                ObjectClass       = $member.ObjectClass
                DistinguishedName = $member.DistinguishedName
            }
        }
    }
    @($memberRows) | Export-Csv -Path (Join-Path $evidencePath 'PrivilegedGroupMembers.csv') -NoTypeInformation -Encoding UTF8

    if ($null -ne $AssessmentResults.LDAPSigning.DomainControllers) {
        @($AssessmentResults.LDAPSigning.DomainControllers) | Export-Csv -Path (Join-Path $evidencePath 'LDAPSigning.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($null -ne $AssessmentResults.PasswordPolicy) {
        @($AssessmentResults.PasswordPolicy) | Export-Csv -Path (Join-Path $evidencePath 'PasswordPolicy.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($null -ne $AssessmentResults.LAPS) {
        @($AssessmentResults.LAPS) | Export-Csv -Path (Join-Path $evidencePath 'LAPSVisibility.csv') -NoTypeInformation -Encoding UTF8
    }

    return $evidencePath
}

function New-ADLiteHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$AssessmentResults,
        [Parameter(Mandatory)] [string]$Path
    )

    function ConvertTo-HtmlSafe {
        param([object]$Value)
        if ($null -eq $Value) { return '' }
        return [System.Net.WebUtility]::HtmlEncode([string]$Value)
    }

    function ConvertTo-ObjectTableHtml {
        param(
            [Parameter(Mandatory)] [string]$Title,
            [object]$Data,
            [string[]]$Properties
        )

        $items = @($Data)
        if ($items.Count -eq 0) {
            return "<div class='card'><h2>$(ConvertTo-HtmlSafe $Title)</h2><p>No values found.</p></div>"
        }

        if (-not $Properties -or $Properties.Count -eq 0) {
            $Properties = @($items[0].PSObject.Properties.Name)
        }

        $header = ($Properties | ForEach-Object { '<th>{0}</th>' -f (ConvertTo-HtmlSafe $_) }) -join ''
        $rows = foreach ($item in $items) {
            $cells = foreach ($property in $Properties) {
                $value = if ($null -ne $item.PSObject.Properties[$property]) { $item.$property } else { '' }
                '<td>{0}</td>' -f (ConvertTo-HtmlSafe $value)
            }
            '<tr>{0}</tr>' -f ($cells -join '')
        }

        return @"
<div class="card">
<h2>$(ConvertTo-HtmlSafe $Title)</h2>
<p>Found values: $($items.Count)</p>
<table>
<tr>$header</tr>
$($rows -join "`n")
</table>
</div>
"@
    }

    $riskSummary = if ($null -ne $AssessmentResults.RiskSummary) { $AssessmentResults.RiskSummary } else { Get-ADLiteRiskSummary -Findings @($AssessmentResults.Findings) }

    $findingsRows = foreach ($finding in @($AssessmentResults.Findings)) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td></tr>' -f `
            (ConvertTo-HtmlSafe $finding.Severity),
            (ConvertTo-HtmlSafe $finding.RiskPoints),
            (ConvertTo-HtmlSafe $finding.Category),
            (ConvertTo-HtmlSafe $finding.FoundCount),
            (ConvertTo-HtmlSafe $finding.Title),
            (ConvertTo-HtmlSafe $finding.Evidence),
            (ConvertTo-HtmlSafe $finding.EvidenceFile),
            (ConvertTo-HtmlSafe $finding.Recommendation)
    }

    $privilegedMemberRows = foreach ($group in @($AssessmentResults.PrivilegedAccess.PrivilegedGroups)) {
        foreach ($member in @($group.Members)) {
            [pscustomobject]@{
                GroupName         = $group.GroupName
                MemberName        = $member.Name
                SamAccountName    = $member.SamAccountName
                ObjectClass       = $member.ObjectClass
                DistinguishedName = $member.DistinguishedName
            }
        }
    }

    $evidenceSections = @()
    $evidenceSections += ConvertTo-ObjectTableHtml -Title 'Domain Controllers - Found Values' -Data $AssessmentResults.Inventory.DomainControllers -Properties @('HostName','Site','OperatingSystem','IPv4Address')
    $evidenceSections += ConvertTo-ObjectTableHtml -Title 'LDAP Signing - Found Values' -Data $AssessmentResults.LDAPSigning.DomainControllers -Properties @('DomainController','Site','OperatingSystem','IPv4Address','LDAPServerIntegrity','Status','FindingState','Error')
    $evidenceSections += ConvertTo-ObjectTableHtml -Title 'AdminSDHolder Protected Objects - Found Values' -Data $AssessmentResults.AdminSDHolder.ProtectedObjects -Properties @('ObjectType','Name','SamAccountName','Enabled','LastLogonDate','WhenChanged','DistinguishedName')
    $evidenceSections += ConvertTo-ObjectTableHtml -Title 'Stale Users - Found Values' -Data $AssessmentResults.StaleObjects.StaleUsers -Properties @('Name','SamAccountName','Enabled','LastLogonDate','DistinguishedName')
    $evidenceSections += ConvertTo-ObjectTableHtml -Title 'Stale Computers - Found Values' -Data $AssessmentResults.StaleObjects.StaleComputers -Properties @('Name','DNSHostName','OperatingSystem','Enabled','LastLogonDate','DistinguishedName')
    $evidenceSections += ConvertTo-ObjectTableHtml -Title 'adminCount Users - Found Values' -Data $AssessmentResults.PrivilegedAccess.AdminCountUsers -Properties @('Name','SamAccountName','Enabled','LastLogonDate','DistinguishedName')
    $evidenceSections += ConvertTo-ObjectTableHtml -Title 'Privileged Group Members - Found Values' -Data $privilegedMemberRows -Properties @('GroupName','MemberName','SamAccountName','ObjectClass','DistinguishedName')
    $evidenceSections += ConvertTo-ObjectTableHtml -Title 'Password Policy - Found Values' -Data $AssessmentResults.PasswordPolicy -Properties @('ComplexityEnabled','MinPasswordLength','MaxPasswordAgeDays','MinPasswordAgeDays','PasswordHistoryCount','ReversibleEncryptionEnabled','LockoutThreshold','LockoutDurationMinutes','LockoutObservationMinutes')
    $evidenceSections += ConvertTo-ObjectTableHtml -Title 'LAPS Visibility - Found Values' -Data $AssessmentResults.LAPS -Properties @('LegacyLAPSAttributeFound','WindowsLAPSAttributeFound','Note')

    $runDate = ConvertTo-HtmlSafe $AssessmentResults.Metadata.RunDate
    $domainName = ConvertTo-HtmlSafe $AssessmentResults.Inventory.DomainName
    $forestName = ConvertTo-HtmlSafe $AssessmentResults.Inventory.ForestName
    $riskScore = ConvertTo-HtmlSafe $riskSummary.RiskScore
    $riskRating = ConvertTo-HtmlSafe $riskSummary.RiskRating

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>Active Directory Security Assessment Lite</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #222; }
h1 { margin-bottom: 4px; }
.card { border: 1px solid #ddd; border-radius: 8px; padding: 16px; margin: 16px 0; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
th { background: #f4f4f4; }
.score { font-size: 32px; font-weight: 700; }
.rating { font-size: 20px; font-weight: 600; }
.small { color: #555; font-size: 12px; }
</style>
</head>
<body>
<h1>Active Directory Security Assessment Lite</h1>
<p>Generated: $runDate</p>
<div class="card">
<h2>Executive Summary</h2>
<p class="score">Risk Score: $riskScore / 100</p>
<p class="rating">Risk Rating: $riskRating</p>
<p>Domain: $domainName</p>
<p>Forest: $forestName</p>
<p>Scoring model: Critical=25, High=15, Medium=8, Low=3, Informational=0. Total is capped at 100.</p>
<p class="small">The report includes full found values in the evidence sections below. Matching CSV evidence files are exported under the Evidence folder.</p>
</div>
<div class="card">
<h2>Findings Summary</h2>
<table>
<tr><th>Severity</th><th>Risk Points</th><th>Category</th><th>Found</th><th>Finding</th><th>Evidence Summary</th><th>Evidence File</th><th>Recommendation</th></tr>
$($findingsRows -join "`n")
</table>
</div>
$($evidenceSections -join "`n")
</body>
</html>
"@

    $html | Out-File -FilePath $Path -Encoding UTF8
}

Export-ModuleMember -Function New-ADLiteFindingSet, Get-ADLiteRiskSummary, Export-ADLiteEvidenceFiles, New-ADLiteHtmlReport
