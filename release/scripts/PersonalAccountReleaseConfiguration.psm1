#requires -Version 7.2

Set-StrictMode -Version Latest

function Assert-PersonalAccountOrigin {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Label
    )

    $invalidMessage = "$Label must be one canonical HTTPS DNS origin."
    if ([string]::IsNullOrEmpty($Value) -or
        $Value.Length -gt 512 -or
        $Value.Trim() -cne $Value) {
        throw $invalidMessage
    }

    foreach ($character in $Value.ToCharArray()) {
        if ([int]$character -gt 127 -or [char]::IsControl($character)) {
            throw $invalidMessage
        }
    }

    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -cne 'https' -or
        -not $uri.IsDefaultPort -or
        $uri.Port -ne 443 -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment) -or
        $uri.AbsolutePath -cne '/' -or
        $uri.HostNameType -ne [UriHostNameType]::Dns -or
        $uri.IsLoopback -or
        [string]::IsNullOrEmpty($uri.Host) -or
        $uri.Host.EndsWith('.', [StringComparison]::Ordinal)) {
        throw $invalidMessage
    }

    $accountHost = $uri.Host.ToLowerInvariant()
    foreach ($label in $accountHost.Split('.', [StringSplitOptions]::None)) {
        if ([string]::IsNullOrEmpty($label) -or $label.Length -gt 63 -or
            -not (($label[0] -ge 'a' -and $label[0] -le 'z') -or
                ($label[0] -ge '0' -and $label[0] -le '9')) -or
            -not (($label[$label.Length - 1] -ge 'a' -and $label[$label.Length - 1] -le 'z') -or
                ($label[$label.Length - 1] -ge '0' -and $label[$label.Length - 1] -le '9'))) {
            throw $invalidMessage
        }

        foreach ($character in $label.ToCharArray()) {
            $isAsciiLetterOrDigit = ($character -ge 'a' -and $character -le 'z') -or
                ($character -ge '0' -and $character -le '9')
            if (-not $isAsciiLetterOrDigit -and $character -ne '-') {
                throw $invalidMessage
            }
        }
    }

    $canonical = "https://$accountHost/"
    if ($canonical -cne $Value -or $uri.AbsoluteUri -cne $Value) {
        throw $invalidMessage
    }

    return $canonical
}

function ConvertFrom-PersonalAccountSelfCheck {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedOrigin
    )

    $invalidMessage = 'Personal account build self-check metadata is invalid.'
    try {
        $canonicalOrigin = Assert-PersonalAccountOrigin `
            -Value $ExpectedOrigin `
            -Label 'ExpectedOrigin'
        if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt (16 * 1024)) {
            throw $invalidMessage
        }

        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $json = $utf8.GetString($Bytes)
        $options = [Text.Json.JsonDocumentOptions]::new()
        $options.AllowTrailingCommas = $false
        $options.CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
        $options.MaxDepth = 8
        $document = [Text.Json.JsonDocument]::Parse($json, $options)
        try {
            if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
                throw $invalidMessage
            }

            $properties = @($document.RootElement.EnumerateObject())
            $expectedNames = @(
                'schemaVersion',
                'product',
                'component',
                'personalAccountOrigin'
            )
            if ($properties.Count -ne $expectedNames.Count) {
                throw $invalidMessage
            }

            $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            for ($index = 0; $index -lt $properties.Count; $index++) {
                if (-not $seen.Add($properties[$index].Name) -or
                    $properties[$index].Name -cne $expectedNames[$index]) {
                    throw $invalidMessage
                }
            }

            if ($properties[0].Value.ValueKind -ne [Text.Json.JsonValueKind]::Number -or
                $properties[0].Value.GetInt32() -ne 1 -or
                $properties[1].Value.ValueKind -ne [Text.Json.JsonValueKind]::String -or
                $properties[1].Value.GetString() -cne 'ensou-dsh-personal' -or
                $properties[2].Value.ValueKind -ne [Text.Json.JsonValueKind]::String -or
                $properties[2].Value.GetString() -cne 'launcher' -or
                $properties[3].Value.ValueKind -ne [Text.Json.JsonValueKind]::String -or
                $properties[3].Value.GetString() -cne $canonicalOrigin) {
                throw $invalidMessage
            }

            $canonicalJson = '{"schemaVersion":1,"product":"ensou-dsh-personal","component":"launcher","personalAccountOrigin":"' +
                $canonicalOrigin + '"}'
            [byte[]]$canonicalBytes = $utf8.GetBytes($canonicalJson)
            try {
                if ($Bytes.Length -ne $canonicalBytes.Length) {
                    throw $invalidMessage
                }
                for ($index = 0; $index -lt $Bytes.Length; $index++) {
                    if ($Bytes[$index] -ne $canonicalBytes[$index]) {
                        throw $invalidMessage
                    }
                }
            }
            finally {
                [Security.Cryptography.CryptographicOperations]::ZeroMemory($canonicalBytes)
            }

            return [pscustomobject][ordered]@{
                schemaVersion = 1
                product = 'ensou-dsh-personal'
                component = 'launcher'
                personalAccountOrigin = $canonicalOrigin
            }
        }
        finally {
            if ($null -ne $document) {
                $document.Dispose()
            }
        }
    }
    catch {
        throw $invalidMessage
    }
}

Export-ModuleMember -Function @(
    'Assert-PersonalAccountOrigin',
    'ConvertFrom-PersonalAccountSelfCheck'
)
