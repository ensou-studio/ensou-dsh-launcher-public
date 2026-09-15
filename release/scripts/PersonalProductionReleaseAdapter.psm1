#requires -Version 7.2

Set-StrictMode -Version Latest

function Get-PersonalProductionClientSigningContract {
    [CmdletBinding()]
    param()

    return @(
        [pscustomobject]@{ Role = 'startup-stub'; FileName = 'Ensou.Dsh.Bootstrapper.exe' },
        [pscustomobject]@{ Role = 'client-bootstrapper'; FileName = 'Ensou.Dsh.ClientBootstrapper.exe' },
        [pscustomobject]@{ Role = 'launcher'; FileName = 'Ensou.Dsh.Launcher.exe' },
        [pscustomobject]@{ Role = 'maintenance'; FileName = 'Ensou.Dsh.Personal.Maintenance.exe' }
    )
}

function Assert-PersonalProductionReleasePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Plan,

        [switch]$AllowHistoricalV1Status
    )

    if ([string]$Plan.edition -cne 'Personal') {
        throw 'Personal production adapter received a plan for another edition.'
    }
    $schemaVersionProperty = $Plan.PSObject.Properties['schemaVersion']
    if ($null -eq $schemaVersionProperty -or
        [int]$schemaVersionProperty.Value -notin @(1, 2)) {
        throw 'Personal production adapter requires a supported plan schemaVersion.'
    }
    if ([int]$schemaVersionProperty.Value -eq 1) {
        if (-not $AllowHistoricalV1Status) {
            throw 'NO-GO: Personal plan schemaVersion 1 is historical Status replay only; every mutating phase requires schemaVersion 2.'
        }

        # Plan v1 is retained only so a current launcher can replay an already
        # committed historical state.  Do not reinterpret its retired signing
        # role contract as a release candidate that can be advanced.
        return
    }
    if ($Plan.PSObject.Properties.Name -ccontains
            'personalPilotTemplateStatus') {
        throw 'NO-GO: Personal Pilot plan is a template pending real release inputs and device evidence.'
    }

    $contract = @(Get-PersonalProductionClientSigningContract)
    $inputs = @($Plan.clientSigningInputs)
    if ($inputs.Count -ne $contract.Count) {
        throw 'Personal production plan must contain the exact four client signing roles.'
    }

    for ($index = 0; $index -lt $contract.Count; $index++) {
        if ([string]$inputs[$index].role -cne [string]$contract[$index].Role -or
            [string]$inputs[$index].fileName -cne [string]$contract[$index].FileName) {
            throw "Personal client signing role order or file name is not canonical at index $index."
        }
    }
}

Export-ModuleMember -Function @(
    'Get-PersonalProductionClientSigningContract',
    'Assert-PersonalProductionReleasePlan'
)
