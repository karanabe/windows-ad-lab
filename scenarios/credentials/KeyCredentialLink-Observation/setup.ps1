#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ScenarioOuName = 'KeyCredentialLink-Lab',
    [string]$SampleSamAccountName = 'kcl.sample',
    [string]$ControlSamAccountName = 'kcl.control',
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'KeyCredentialLink-Observation'
$script:Marker = 'windows-ad-lab:KeyCredentialLink-Observation'
$script:RootOuName = 'LAB'
$script:Changed = $false
$script:KeyCredentialAttribute = 'msDS-KeyCredentialLink'

$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop

function Assert-SimpleRdnValue {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$Name cannot be empty."
    }
    if ($Value -ne $Value.Trim()) {
        throw "$Name cannot start or end with whitespace: '$Value'"
    }
    if ($Value -match '[,=+<>#;"\\]') {
        throw "$Name contains a DN-special character rejected by this lab: '$Value'"
    }
}

function Assert-SamAccountName {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($Value -notmatch '^[A-Za-z0-9._-]{1,20}$') {
        throw "$Name must be a valid 1-20 character sAMAccountName: '$Value'"
    }
}

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
}

function Get-AdOrganizationalUnitOrNull {
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)

    try {
        return Get-ADOrganizationalUnit -Identity $DistinguishedName -Properties adminDescription, Description, ProtectedFromAccidentalDeletion @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-ScenarioUserBySamOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties adminDescription, Description, DisplayName, Department, msDS-KeyCredentialLink, UserPrincipalName @AdServerParameters)
    if ($users.Count -gt 1) {
        throw "Multiple users were returned for sAMAccountName '$SamAccountName'."
    }
    if ($users.Count -eq 0) {
        return $null
    }
    return $users[0]
}

function Add-ByteRange {
    param(
        [System.Collections.Generic.List[byte]]$List,
        [AllowNull()][byte[]]$Bytes
    )

    if ($null -eq $Bytes) {
        return
    }
    foreach ($byte in $Bytes) {
        $List.Add($byte)
    }
}

function Get-LeUInt16Bytes {
    param([Parameter(Mandatory = $true)][UInt16]$Value)

    $bytes = [BitConverter]::GetBytes($Value)
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    return $bytes
}

function Get-LeUInt32Bytes {
    param([Parameter(Mandatory = $true)][UInt32]$Value)

    $bytes = [BitConverter]::GetBytes($Value)
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    return $bytes
}

function Get-LeInt64Bytes {
    param([Parameter(Mandatory = $true)][Int64]$Value)

    $bytes = [BitConverter]::GetBytes($Value)
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    return $bytes
}

function ConvertTo-HexString {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $builder = New-Object System.Text.StringBuilder
    foreach ($byte in $Bytes) {
        [void]$builder.AppendFormat('{0:X2}', $byte)
    }
    return $builder.ToString()
}

function Get-Sha256Hash {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return $sha256.ComputeHash($Bytes)
    }
    finally {
        $sha256.Dispose()
    }
}

function New-KeyCredentialEntry {
    param(
        [Parameter(Mandatory = $true)][byte]$Identifier,
        [Parameter(Mandatory = $true)][byte[]]$Value
    )

    if ($Value.Length -gt [UInt16]::MaxValue) {
        throw "KEYCREDENTIALLINK_ENTRY value is too large: $($Value.Length) bytes."
    }

    $bytes = New-Object 'System.Collections.Generic.List[byte]'
    Add-ByteRange -List $bytes -Bytes (Get-LeUInt16Bytes -Value ([UInt16]$Value.Length))
    $bytes.Add($Identifier)
    Add-ByteRange -List $bytes -Bytes $Value
    return $bytes.ToArray()
}

function New-NgcRsaPublicKeyBlob {
    $rsa = New-Object -TypeName System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 2048
    $rsa.PersistKeyInCsp = $false
    try {
        $parameters = $rsa.ExportParameters($false)
    }
    finally {
        $rsa.Clear()
    }

    $keyMaterial = New-Object 'System.Collections.Generic.List[byte]'
    Add-ByteRange -List $keyMaterial -Bytes (Get-LeUInt32Bytes -Value ([UInt32]0x31415352))
    Add-ByteRange -List $keyMaterial -Bytes (Get-LeUInt32Bytes -Value ([UInt32]($parameters.Modulus.Length * 8)))
    Add-ByteRange -List $keyMaterial -Bytes (Get-LeUInt32Bytes -Value ([UInt32]$parameters.Exponent.Length))
    Add-ByteRange -List $keyMaterial -Bytes (Get-LeUInt32Bytes -Value ([UInt32]$parameters.Modulus.Length))
    Add-ByteRange -List $keyMaterial -Bytes (Get-LeUInt32Bytes -Value ([UInt32]0))
    Add-ByteRange -List $keyMaterial -Bytes (Get-LeUInt32Bytes -Value ([UInt32]0))
    Add-ByteRange -List $keyMaterial -Bytes $parameters.Exponent
    Add-ByteRange -List $keyMaterial -Bytes $parameters.Modulus
    return $keyMaterial.ToArray()
}

function New-KeyCredentialLinkDnBinary {
    param([Parameter(Mandatory = $true)][string]$OwnerDistinguishedName)

    $keyMaterial = New-NgcRsaPublicKeyBlob
    $keyId = Get-Sha256Hash -Bytes $keyMaterial
    $deviceId = [Guid]::NewGuid().ToByteArray()
    $creationTime = [DateTime]::UtcNow.ToFileTimeUtc()

    $entryKeyMaterial = New-KeyCredentialEntry -Identifier 0x03 -Value $keyMaterial
    $entryKeyUsage = New-KeyCredentialEntry -Identifier 0x04 -Value ([byte[]]@(0x01))
    $entryKeySource = New-KeyCredentialEntry -Identifier 0x05 -Value ([byte[]]@(0x00))
    $entryDeviceId = New-KeyCredentialEntry -Identifier 0x06 -Value $deviceId
    $entryCreationTime = New-KeyCredentialEntry -Identifier 0x09 -Value (Get-LeInt64Bytes -Value $creationTime)

    $hashInput = New-Object 'System.Collections.Generic.List[byte]'
    foreach ($entry in @($entryKeyMaterial, $entryKeyUsage, $entryKeySource, $entryDeviceId, $entryCreationTime)) {
        Add-ByteRange -List $hashInput -Bytes $entry
    }

    $entryKeyId = New-KeyCredentialEntry -Identifier 0x01 -Value $keyId
    $entryKeyHash = New-KeyCredentialEntry -Identifier 0x02 -Value (Get-Sha256Hash -Bytes $hashInput.ToArray())

    $blob = New-Object 'System.Collections.Generic.List[byte]'
    Add-ByteRange -List $blob -Bytes (Get-LeUInt32Bytes -Value ([UInt32]0x00000200))
    foreach ($entry in @($entryKeyId, $entryKeyHash, $entryKeyMaterial, $entryKeyUsage, $entryKeySource, $entryDeviceId, $entryCreationTime)) {
        Add-ByteRange -List $blob -Bytes $entry
    }

    $blobBytes = $blob.ToArray()
    $hex = ConvertTo-HexString -Bytes $blobBytes
    $deviceGuid = New-Object -TypeName System.Guid -ArgumentList (, $deviceId)
    return [pscustomobject]@{
        DnBinary          = "B:$($hex.Length):${hex}:$OwnerDistinguishedName"
        KeyId             = (ConvertTo-HexString -Bytes $keyId)
        DeviceId          = $deviceGuid.ToString()
        KeyMaterialBytes  = $keyMaterial.Length
        BlobBytes         = $blobBytes.Length
        CreationTimeUtc   = [DateTime]::FromFileTimeUtc($creationTime).ToString('o')
    }
}

function ConvertTo-StringArray {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return @()
    }
    if ($Value -is [array] -and -not ($Value -is [byte[]])) {
        return @($Value | ForEach-Object { [string]$_ })
    }
    if ($Value -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
        return @($Value | ForEach-Object { [string]$_ })
    }
    return @([string]$Value)
}

function Ensure-ScenarioOu {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][string]$ParentDistinguishedName
    )

    $ou = Get-AdOrganizationalUnitOrNull -DistinguishedName $DistinguishedName
    if ($null -eq $ou) {
        if ($PSCmdlet.ShouldProcess($DistinguishedName, 'Create scenario OU')) {
            New-ADOrganizationalUnit -Name $ScenarioOuName -Path $ParentDistinguishedName -Description 'LAB ONLY: KeyCredentialLink observation objects' -ProtectedFromAccidentalDeletion $true -OtherAttributes @{ adminDescription = $script:Marker } @AdServerParameters -ErrorAction Stop | Out-Null
            $script:Changed = $true
        }
        return
    }

    if ([string]$ou.adminDescription -cne $script:Marker) {
        throw "OU '$DistinguishedName' already exists but is not marked for this scenario. Refusing to modify it."
    }

    $replace = @{}
    if ([string]$ou.Description -cne 'LAB ONLY: KeyCredentialLink observation objects') {
        $replace['description'] = 'LAB ONLY: KeyCredentialLink observation objects'
    }
    if ($replace.Count -gt 0 -and $PSCmdlet.ShouldProcess($DistinguishedName, 'Update scenario OU metadata')) {
        Set-ADOrganizationalUnit -Identity $DistinguishedName -Replace $replace @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
    if (-not [bool]$ou.ProtectedFromAccidentalDeletion -and $PSCmdlet.ShouldProcess($DistinguishedName, 'Enable accidental deletion protection')) {
        Set-ADOrganizationalUnit -Identity $DistinguishedName -ProtectedFromAccidentalDeletion $true @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
}

function Ensure-ScenarioUser {
    param(
        [Parameter(Mandatory = $true)][string]$SamAccountName,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$DomainDnsName
    )

    $user = Get-ScenarioUserBySamOrNull -SamAccountName $SamAccountName
    if ($null -eq $user) {
        if ($PSCmdlet.ShouldProcess($SamAccountName, "Create disabled scenario user in $Path")) {
            New-ADUser `
                -Name $Name `
                -DisplayName $Name `
                -SamAccountName $SamAccountName `
                -UserPrincipalName "$SamAccountName@$DomainDnsName" `
                -Path $Path `
                -Description $Description `
                -Department 'Learning' `
                -Enabled $false `
                -OtherAttributes @{ adminDescription = $script:Marker } `
                @AdServerParameters `
                -ErrorAction Stop
            $script:Changed = $true
        }
        return (Get-ScenarioUserBySamOrNull -SamAccountName $SamAccountName)
    }

    if ([string]$user.adminDescription -cne $script:Marker -or [string]$user.DistinguishedName -ine "CN=$Name,$Path") {
        throw "User '$SamAccountName' already exists outside this scenario. Refusing to modify it."
    }

    $replace = @{}
    foreach ($mapping in @(
        @{ Attribute = 'displayName'; Current = [string]$user.DisplayName; Desired = $Name },
        @{ Attribute = 'description'; Current = [string]$user.Description; Desired = $Description },
        @{ Attribute = 'department'; Current = [string]$user.Department; Desired = 'Learning' },
        @{ Attribute = 'userPrincipalName'; Current = [string]$user.UserPrincipalName; Desired = "$SamAccountName@$DomainDnsName" },
        @{ Attribute = 'adminDescription'; Current = [string]$user.adminDescription; Desired = $script:Marker }
    )) {
        if ($mapping.Current -cne $mapping.Desired) {
            $replace[[string]$mapping.Attribute] = [string]$mapping.Desired
        }
    }

    if ($replace.Count -gt 0 -and $PSCmdlet.ShouldProcess($SamAccountName, 'Update scenario user metadata')) {
        Set-ADObject -Identity $user.DistinguishedName -Replace $replace @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
    if ([bool]$user.Enabled -and $PSCmdlet.ShouldProcess($SamAccountName, 'Disable scenario user')) {
        Disable-ADAccount -Identity $user.DistinguishedName @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }

    return (Get-ScenarioUserBySamOrNull -SamAccountName $SamAccountName)
}

function Ensure-SampleKeyCredentialLink {
    param([Parameter(Mandatory = $true)]$User)

    $values = @(ConvertTo-StringArray -Value $User.($script:KeyCredentialAttribute))
    if ($values.Count -gt 0) {
        Write-Host "Sample user already has $($values.Count) msDS-KeyCredentialLink value(s); leaving them unchanged."
        return $null
    }

    $credential = New-KeyCredentialLinkDnBinary -OwnerDistinguishedName ([string]$User.DistinguishedName)
    if ($PSCmdlet.ShouldProcess($User.DistinguishedName, 'Add public-key-only msDS-KeyCredentialLink sample value')) {
        Set-ADObject -Identity $User.DistinguishedName -Add @{ 'msDS-KeyCredentialLink' = $credential.DnBinary } @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
        Write-Host 'Added an observation-only KeyCredentialLink value. The private key was discarded and the account remains disabled.'
    }
    return $credential
}

Assert-SimpleRdnValue -Value $ScenarioOuName -Name 'ScenarioOuName'
Assert-SamAccountName -Value $SampleSamAccountName -Name 'SampleSamAccountName'
Assert-SamAccountName -Value $ControlSamAccountName -Name 'ControlSamAccountName'
if ($SampleSamAccountName -ieq $ControlSamAccountName) {
    throw 'SampleSamAccountName and ControlSamAccountName must be different.'
}

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}

$domainDn = [string]$domain.DistinguishedName
$rootOuDn = "OU=$script:RootOuName,$domainDn"
if ($null -eq (Get-AdOrganizationalUnitOrNull -DistinguishedName $rootOuDn)) {
    throw "Baseline root OU '$rootOuDn' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
}

$scenarioOuDn = "OU=$ScenarioOuName,$rootOuDn"
Ensure-ScenarioOu -DistinguishedName $scenarioOuDn -ParentDistinguishedName $rootOuDn

$sampleUser = Ensure-ScenarioUser `
    -SamAccountName $SampleSamAccountName `
    -Name 'KCL Sample User' `
    -Description 'LAB ONLY: user with an observation-only msDS-KeyCredentialLink value' `
    -Path $scenarioOuDn `
    -DomainDnsName ([string]$domain.DNSRoot)

$controlUser = Ensure-ScenarioUser `
    -SamAccountName $ControlSamAccountName `
    -Name 'KCL Control User' `
    -Description 'LAB ONLY: comparison user without msDS-KeyCredentialLink' `
    -Path $scenarioOuDn `
    -DomainDnsName ([string]$domain.DNSRoot)

$keyCredential = $null
if ($null -ne $sampleUser) {
    $keyCredential = Ensure-SampleKeyCredentialLink -User $sampleUser
    $sampleUser = Get-ScenarioUserBySamOrNull -SamAccountName $SampleSamAccountName
}
if ($null -ne $controlUser) {
    $controlUser = Get-ScenarioUserBySamOrNull -SamAccountName $ControlSamAccountName
}

[pscustomobject]@{
    Scenario                   = $script:ScenarioName
    Changed                    = $script:Changed
    Baseline                   = '06-ADCS-HTTP-CDP'
    ScenarioOU                 = $scenarioOuDn
    SampleUser                 = if ($null -eq $sampleUser) { '<not created>' } else { $sampleUser.DistinguishedName }
    SampleKeyCredentialValues  = if ($null -eq $sampleUser) { 0 } else { @(ConvertTo-StringArray -Value $sampleUser.($script:KeyCredentialAttribute)).Count }
    ControlUser                = if ($null -eq $controlUser) { '<not created>' } else { $controlUser.DistinguishedName }
    ControlKeyCredentialValues = if ($null -eq $controlUser) { 0 } else { @(ConvertTo-StringArray -Value $controlUser.($script:KeyCredentialAttribute)).Count }
    GeneratedKeyId             = if ($null -eq $keyCredential) { '<unchanged>' } else { $keyCredential.KeyId }
}
