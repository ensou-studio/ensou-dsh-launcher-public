#requires -Version 7.2

Set-StrictMode -Version Latest

function Get-EnterpriseProductionClientSigningContract {
    [CmdletBinding()]
    param()

    return @(
        [pscustomobject]@{ Role = 'bootstrapper'; FileName = 'Ensou.Dsh.Enterprise.Bootstrapper.exe' },
        [pscustomobject]@{ Role = 'launcher'; FileName = 'Ensou.Dsh.Enterprise.Launcher.exe' },
        [pscustomobject]@{ Role = 'client-bootstrapper'; FileName = 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe' },
        [pscustomobject]@{ Role = 'maintenance'; FileName = 'Ensou.Dsh.Enterprise.Maintenance.exe' }
    )
}

function Assert-EnterpriseProductionReleasePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Plan
    )

    if ([string]$Plan.edition -cne 'Enterprise') {
        throw 'Enterprise production adapter received a plan for another edition.'
    }
    if ([int]$Plan.schemaVersion -eq 2) {
        $pilotTrustAnchor =
            $Plan.PSObject.Properties['pilotEvidenceTrustPolicySha256']
        if ($null -eq $pilotTrustAnchor -or
            [string]$pilotTrustAnchor.Value -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Enterprise production plan v2 must anchor the exact Pilot evidence trust-policy SHA-256 before r1.'
        }
    }

    $contract = @(Get-EnterpriseProductionClientSigningContract)
    $inputs = @($Plan.clientSigningInputs)
    if ($inputs.Count -ne $contract.Count) {
        throw 'Enterprise production plan must contain the exact four client signing roles.'
    }

    for ($index = 0; $index -lt $contract.Count; $index++) {
        if ([string]$inputs[$index].role -cne [string]$contract[$index].Role -or
            [string]$inputs[$index].fileName -cne [string]$contract[$index].FileName) {
            throw "Enterprise client signing role order or file name is not canonical at index $index."
        }
    }
}

Export-ModuleMember -Function @(
    'Get-EnterpriseProductionClientSigningContract',
    'Assert-EnterpriseProductionReleasePlan'
)
