<#
.SYNOPSIS
    Runs a lightweight read-only Active Directory security assessment.

.DESCRIPTION
    Active Directory Security Assessment Lite collects common AD security posture signals including
    inventory, stale objects, privileged group membership, password policy, LAPS visibility,
    LDAP signing, AdminSDHolder/adminCount exposure, and basic delegation exposure.

.NOTES
    Community/GitHub edition. Uses sanitized, generic logic only.
    This script is read-only and does not modify Active Directory.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\Temp\ADSecurityAssessmentLite",
    [switch]$GenerateHTML,
    [switch]$GenerateJSON,
    [switch]$GenerateCSV,
    [int]$StaleDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModulePath = Join-Path $ScriptRoot "Modules"

$modules = @(
    "AD.Inventory.psm1",
    "AD.StaleObjects.psm1",
    "AD.PrivilegedAccess.psm1",
    "AD.PasswordPolicy.psm1",
    "AD.LAPS.psm1",
    "AD.LDAPSigning.psm1",
    "AD.AdminSDHolder.psm1",
    "AD.Reporting.psm1"
)

foreach ($module in $modules) {
    Import-Module (Join-Path $ModulePath $module) -Force
}

if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$LogPath = Join-Path $OutputPath "AD_Assessment.log"

function Write-AssessmentLog {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet("INFO","WARN","ERROR")] [string]$Level = "INFO"
    )

    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $LogPath -Value $line
    Write-Host $line
}

try {
    Write-AssessmentLog "Starting Active Directory Security Assessment Lite"

    Import-Module ActiveDirectory -ErrorAction Stop

    $results = [ordered]@{
        Metadata = [ordered]@{
            ToolName    = "Active Directory Security Assessment Lite"
            Version     = "1.0.0-community"
            RunDate     = (Get-Date).ToString("s")
            Computer    = $env:COMPUTERNAME
            User        = $env:USERNAME
        }
        Inventory        = $null
        StaleObjects     = $null
        PrivilegedAccess = $null
        PasswordPolicy   = $null
        LAPS             = $null
        LDAPSigning      = $null
        AdminSDHolder    = $null
        Findings         = @()
        RiskSummary      = $null
    }

    Write-AssessmentLog "Collecting forest and domain inventory"
    $results.Inventory = Get-ADLiteInventory

    Write-AssessmentLog "Checking stale users and computers"
    $results.StaleObjects = Get-ADLiteStaleObjects -StaleDays $StaleDays

    Write-AssessmentLog "Reviewing privileged access exposure"
    $results.PrivilegedAccess = Get-ADLitePrivilegedAccess

    Write-AssessmentLog "Checking password policy"
    $results.PasswordPolicy = Get-ADLitePasswordPolicy

    Write-AssessmentLog "Checking LAPS visibility"
    $results.LAPS = Get-ADLiteLAPSVisibility

    Write-AssessmentLog "Checking LDAP signing on domain controllers"
    $results.LDAPSigning = Get-ADLiteLDAPSigning

    Write-AssessmentLog "Checking AdminSDHolder/adminCount protected objects"
    $results.AdminSDHolder = Get-ADLiteAdminSDHolderAssessment

    Write-AssessmentLog "Building findings"
    $results.Findings = New-ADLiteFindingSet -AssessmentResults $results

    Write-AssessmentLog "Calculating risk score"
    $results.RiskSummary = Get-ADLiteRiskSummary -Findings @($results.Findings)
    Write-AssessmentLog "Risk Score: $($results.RiskSummary.RiskScore) / 100 ($($results.RiskSummary.RiskRating))"

    Write-AssessmentLog "Exporting evidence files"
    $evidencePath = Export-ADLiteEvidenceFiles -AssessmentResults $results -OutputPath $OutputPath
    Write-AssessmentLog "Evidence files saved to $evidencePath"

    if ($GenerateJSON) {
        $jsonPath = Join-Path $OutputPath "AD_Assessment_Results.json"
        $results | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-AssessmentLog "JSON output saved to $jsonPath"
    }

    if ($GenerateCSV) {
        $csvPath = Join-Path $OutputPath "AD_Assessment_Findings.csv"
        $results.Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-AssessmentLog "CSV output saved to $csvPath"
    }

    if ($GenerateHTML) {
        $htmlPath = Join-Path $OutputPath "AD_Assessment_Summary.html"
        New-ADLiteHtmlReport -AssessmentResults $results -Path $htmlPath
        Write-AssessmentLog "HTML output saved to $htmlPath"
    }

    Write-AssessmentLog "Assessment complete"
}
catch {
    Write-AssessmentLog -Level ERROR -Message $_.Exception.Message
    throw
}
