#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ScenarioOuName = 'KeyCredentialLink-Lab',
    [string]$SampleSamAccountName = 'kcl.sample',
    [string]$ControlSamAccountName = 'kcl.control',
    [string]$Server,
    [switch]$IncludeInheritedAcl,
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'KeyCredentialLink-Observation'
$script:Marker = 'windows-ad-lab:KeyCredentialLink-Observation'
$script:RootOuName = 'LAB'
$script:KeyCredentialAttribute = 'msDS-KeyCredentialLink'
$script:KeyCredentialSchemaGuid = [Guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063'
$script:BaselineValue = 'Absent in 06-ADCS-HTTP-CDP'

$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
}

function ConvertTo-HexString {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $builder = New-Object System.Text.StringBuilder
    foreach ($byte in $Bytes) {
        [void]$builder.AppendFormat('{0:X2}', $byte)
    }
    return $builder.ToString()
}

function ConvertFrom-HexString {
    param([Parameter(Mandatory = $true)][string]$Hex)

    if (($Hex.Length % 2) -ne 0) {
        throw 'Hex string length must be even.'
    }
    $bytes = New-Object 'byte[]' ($Hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    return $bytes
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

function ConvertTo-DisplayValue {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return '<not set>'
    }
    if ($Value -is [byte[]]) {
        $hash = ConvertTo-HexString -Bytes (Get-Sha256Hash -Bytes $Value)
        return "bytes=$($Value.Length);sha256=$($hash.Substring(0, 16))..."
    }
    if ($Value -is [DateTime]) {
        return $Value.ToString('o')
    }
    if ($Value -is [array] -and -not ($Value -is [string])) {
        return ((@($Value) | ForEach-Object { ConvertTo-DisplayValue -Value $_ }) -join '; ')
    }
    if ($Value -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
        return ((@($Value) | ForEach-Object { ConvertTo-DisplayValue -Value $_ }) -join '; ')
    }

    $text = [string]$Value
    if ($text.Length -gt 180) {
        return "$($text.Substring(0, 180))..."
    }
    return $text
}

function New-DiffRow {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Surface,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Property,
        [AllowNull()]$Scenario
    )

    return [pscustomobject]([ordered]@{
        Source   = $Source
        Surface  = $Surface
        Target   = $Target
        Property = $Property
        Baseline = $script:BaselineValue
        Scenario = ConvertTo-DisplayValue -Value $Scenario
    })
}

function Get-AdObjectOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [string[]]$Properties = @()
    )

    try {
        return Get-ADObject -Identity $DistinguishedName -Properties $Properties @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-ScenarioUserBySamOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties adminDescription, Department, Description, DisplayName, msDS-KeyCredentialLink, userAccountControl, UserPrincipalName, whenChanged, whenCreated @AdServerParameters)
    if ($users.Count -gt 1) {
        throw "Multiple users were returned for sAMAccountName '$SamAccountName'."
    }
    if ($users.Count -eq 0) {
        return $null
    }
    return $users[0]
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

function Get-KeyCredentialEntryName {
    param([Parameter(Mandatory = $true)][byte]$Identifier)

    switch ($Identifier) {
        0x01 { return 'KeyID' }
        0x02 { return 'KeyHash' }
        0x03 { return 'KeyMaterial' }
        0x04 { return 'KeyUsage' }
        0x05 { return 'KeySource' }
        0x06 { return 'DeviceId' }
        0x07 { return 'CustomKeyInformation' }
        0x08 { return 'KeyApproximateLastLogonTimeStamp' }
        0x09 { return 'KeyCreationTime' }
        default { return "Unknown(0x$($Identifier.ToString('X2')))" }
    }
}

function ConvertFrom-KeyCredentialLinkValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value -notmatch '^B:(\d+):([0-9A-Fa-f]*):(.*)$') {
        return [pscustomobject]@{
            Format = 'Unparsed'
            Error  = 'Value is not in DN-Binary string format.'
        }
    }

    $declaredHexLength = [int]$Matches[1]
    $hex = [string]$Matches[2]
    $ownerDn = [string]$Matches[3]
    $bytes = ConvertFrom-HexString -Hex $hex
    if ($bytes.Length -lt 4) {
        return [pscustomobject]@{
            Format = 'Invalid'
            Error  = 'Blob is shorter than the 4-byte version field.'
        }
    }

    $version = [BitConverter]::ToUInt32($bytes, 0)
    $offset = 4
    $entries = New-Object 'System.Collections.Generic.List[object]'
    while ($offset -lt $bytes.Length) {
        if (($offset + 3) -gt $bytes.Length) {
            throw "Truncated KEYCREDENTIALLINK_ENTRY header at offset $offset."
        }
        $start = $offset
        $length = [BitConverter]::ToUInt16($bytes, $offset)
        $offset += 2
        $identifier = $bytes[$offset]
        $offset += 1
        if (($offset + $length) -gt $bytes.Length) {
            throw "Truncated KEYCREDENTIALLINK_ENTRY value at offset $offset."
        }
        $entryValue = New-Object 'byte[]' $length
        [Array]::Copy($bytes, $offset, $entryValue, 0, $length)
        $offset += $length
        $entries.Add([pscustomobject]@{
            Identifier = $identifier
            Name       = Get-KeyCredentialEntryName -Identifier $identifier
            Length     = $length
            Value      = $entryValue
            Start      = $start
            End        = $offset
        })
    }

    $keyMaterial = @($entries | Where-Object Identifier -eq 0x03 | Select-Object -First 1)
    $keyId = @($entries | Where-Object Identifier -eq 0x01 | Select-Object -First 1)
    $keyHash = @($entries | Where-Object Identifier -eq 0x02 | Select-Object -First 1)
    $keyUsage = @($entries | Where-Object Identifier -eq 0x04 | Select-Object -First 1)
    $keySource = @($entries | Where-Object Identifier -eq 0x05 | Select-Object -First 1)
    $deviceId = @($entries | Where-Object Identifier -eq 0x06 | Select-Object -First 1)
    $creationTime = @($entries | Where-Object Identifier -eq 0x09 | Select-Object -First 1)

    $keyIdMatches = '<not checked>'
    if ($keyMaterial.Count -gt 0 -and $keyId.Count -gt 0) {
        $computedKeyId = ConvertTo-HexString -Bytes (Get-Sha256Hash -Bytes $keyMaterial[0].Value)
        $storedKeyId = ConvertTo-HexString -Bytes $keyId[0].Value
        $keyIdMatches = [string]($computedKeyId -ieq $storedKeyId)
    }

    $keyHashMatches = '<not checked>'
    if ($keyHash.Count -gt 0) {
        $tailLength = $bytes.Length - [int]$keyHash[0].End
        $tail = New-Object 'byte[]' $tailLength
        if ($tailLength -gt 0) {
            [Array]::Copy($bytes, [int]$keyHash[0].End, $tail, 0, $tailLength)
        }
        $computedKeyHash = ConvertTo-HexString -Bytes (Get-Sha256Hash -Bytes $tail)
        $storedKeyHash = ConvertTo-HexString -Bytes $keyHash[0].Value
        $keyHashMatches = [string]($computedKeyHash -ieq $storedKeyHash)
    }

    $usageText = '<not set>'
    if ($keyUsage.Count -gt 0 -and $keyUsage[0].Value.Length -eq 1) {
        switch ($keyUsage[0].Value[0]) {
            0x01 { $usageText = 'KEY_USAGE_NGC' }
            0x07 { $usageText = 'KEY_USAGE_FIDO' }
            0x08 { $usageText = 'KEY_USAGE_FEK' }
            default { $usageText = "Unknown(0x$($keyUsage[0].Value[0].ToString('X2')))" }
        }
    }

    $sourceText = '<not set>'
    if ($keySource.Count -gt 0 -and $keySource[0].Value.Length -eq 1) {
        if ($keySource[0].Value[0] -eq 0x00) {
            $sourceText = 'KEY_SOURCE_AD'
        }
        else {
            $sourceText = "Unknown(0x$($keySource[0].Value[0].ToString('X2')))"
        }
    }

    $deviceText = '<not set>'
    if ($deviceId.Count -gt 0 -and $deviceId[0].Value.Length -eq 16) {
        $deviceGuid = New-Object -TypeName System.Guid -ArgumentList (, $deviceId[0].Value)
        $deviceText = $deviceGuid.ToString()
    }

    $creationText = '<not set>'
    if ($creationTime.Count -gt 0 -and $creationTime[0].Value.Length -eq 8) {
        try {
            $creationText = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($creationTime[0].Value, 0)).ToString('o')
        }
        catch {
            $creationText = "Invalid FILETIME: $($_.Exception.Message)"
        }
    }

    return [pscustomobject]@{
        Format            = 'DN-Binary'
        OwnerDN           = $ownerDn
        DeclaredHexLength = $declaredHexLength
        ActualHexLength   = $hex.Length
        BlobBytes         = $bytes.Length
        Version           = ('0x{0:X8}' -f $version)
        EntryCount        = $entries.Count
        EntryNames        = ((@($entries) | ForEach-Object { $_.Name }) -join ',')
        KeyId             = if ($keyId.Count -eq 0) { '<not set>' } else { ConvertTo-HexString -Bytes $keyId[0].Value }
        KeyIdMatches      = $keyIdMatches
        KeyHashMatches    = $keyHashMatches
        KeyMaterialBytes  = if ($keyMaterial.Count -eq 0) { 0 } else { $keyMaterial[0].Length }
        KeyUsage          = $usageText
        KeySource         = $sourceText
        DeviceId          = $deviceText
        KeyCreationTime   = $creationText
    }
}

function Ensure-AdDrive {
    if ($null -ne (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
        return
    }

    $driveParameters = @{
        Name        = 'AD'
        PSProvider  = 'ActiveDirectory'
        Root        = ''
        Scope       = 'Script'
        ErrorAction = 'Stop'
    }
    if ($AdServerParameters.ContainsKey('Server')) {
        $driveParameters['Server'] = $AdServerParameters['Server']
    }
    New-PSDrive @driveParameters | Out-Null
}

function Test-Right {
    param(
        [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectoryRights]$Rights,
        [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectoryRights]$Right
    )

    return (($Rights -band $Right) -eq $Right)
}

function Test-KeyCredentialWriteCapableAce {
    param([Parameter(Mandatory = $true)]$AccessRule)

    if ([string]$AccessRule.AccessControlType -ne 'Allow') {
        return $false
    }

    $rights = $AccessRule.ActiveDirectoryRights
    if (Test-Right -Rights $rights -Right ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) { return $true }
    if (Test-Right -Rights $rights -Right ([System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)) { return $true }
    if (Test-Right -Rights $rights -Right ([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)) { return $true }
    if (Test-Right -Rights $rights -Right ([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)) { return $true }

    $objectType = [Guid]$AccessRule.ObjectType
    $appliesToAllProperties = ($objectType -eq [Guid]::Empty)
    $appliesToKeyCredentialLink = ($objectType -eq $script:KeyCredentialSchemaGuid)
    if ((Test-Right -Rights $rights -Right ([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)) -and ($appliesToAllProperties -or $appliesToKeyCredentialLink)) {
        return $true
    }
    return $false
}

function Format-Ace {
    param([Parameter(Mandatory = $true)]$AccessRule)

    return "Identity=$($AccessRule.IdentityReference);Type=$($AccessRule.AccessControlType);Rights=$($AccessRule.ActiveDirectoryRights);Inherited=$($AccessRule.IsInherited);ObjectType=$($AccessRule.ObjectType)"
}

function Add-AdObjectRows {
    param(
        [System.Collections.Generic.List[object]]$Rows,
        [Parameter(Mandatory = $true)][string]$Target,
        [AllowNull()]$Object,
        [string[]]$Properties
    )

    if ($null -eq $Object) {
        return
    }

    $Rows.Add((New-DiffRow -Source 'PowerShell' -Surface 'AD object attributes' -Target $Target -Property 'objectClass' -Scenario $Object.ObjectClass))
    foreach ($propertyName in $Properties) {
        if ($Object.PSObject.Properties.Name -contains $propertyName) {
            $Rows.Add((New-DiffRow -Source 'PowerShell' -Surface 'AD object attributes' -Target $Target -Property $propertyName -Scenario $Object.$propertyName))
        }
    }
}

function Add-KeyCredentialRows {
    param(
        [System.Collections.Generic.List[object]]$Rows,
        [Parameter(Mandatory = $true)][string]$Target,
        [AllowNull()]$User
    )

    if ($null -eq $User) {
        return
    }

    $values = @(ConvertTo-StringArray -Value $User.($script:KeyCredentialAttribute))
    $Rows.Add((New-DiffRow -Source 'PowerShell' -Surface 'msDS-KeyCredentialLink' -Target $Target -Property 'ValueCount' -Scenario $values.Count))
    for ($index = 0; $index -lt $values.Count; $index++) {
        $parsed = ConvertFrom-KeyCredentialLinkValue -Value ([string]$values[$index])
        foreach ($propertyName in @('Format', 'OwnerDN', 'DeclaredHexLength', 'ActualHexLength', 'BlobBytes', 'Version', 'EntryCount', 'EntryNames', 'KeyId', 'KeyIdMatches', 'KeyHashMatches', 'KeyMaterialBytes', 'KeyUsage', 'KeySource', 'DeviceId', 'KeyCreationTime')) {
            if ($parsed.PSObject.Properties.Name -contains $propertyName) {
                $Rows.Add((New-DiffRow -Source 'PowerShell' -Surface 'msDS-KeyCredentialLink' -Target $Target -Property "Value[$index].$propertyName" -Scenario $parsed.$propertyName))
            }
        }
        if ($parsed.PSObject.Properties.Name -contains 'Error') {
            $Rows.Add((New-DiffRow -Source 'PowerShell' -Surface 'msDS-KeyCredentialLink' -Target $Target -Property "Value[$index].Error" -Scenario $parsed.Error))
        }
    }
}

function Add-AclRows {
    param(
        [System.Collections.Generic.List[object]]$Rows,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$DistinguishedName
    )

    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$DistinguishedName"
    $accessRules = @($acl.Access)
    $explicitRules = @($accessRules | Where-Object { -not $_.IsInherited })
    $inheritedRules = @($accessRules | Where-Object { $_.IsInherited })
    $Rows.Add((New-DiffRow -Source 'PowerShell' -Surface 'Owner' -Target $Target -Property 'Owner' -Scenario $acl.Owner))
    $Rows.Add((New-DiffRow -Source 'PowerShell' -Surface 'ACL' -Target $Target -Property 'AccessRuleCount' -Scenario $accessRules.Count))
    $Rows.Add((New-DiffRow -Source 'PowerShell' -Surface 'ACL' -Target $Target -Property 'ExplicitAccessRuleCount' -Scenario $explicitRules.Count))
    $Rows.Add((New-DiffRow -Source 'PowerShell' -Surface 'ACL' -Target $Target -Property 'InheritedAccessRuleCount' -Scenario $inheritedRules.Count))

    $rulesToShow = if ($IncludeInheritedAcl) { $accessRules } else { $explicitRules }
    $ruleIndex = 0
    foreach ($rule in $rulesToShow) {
        $Rows.Add((New-DiffRow -Source 'PowerShell' -Surface 'ACL' -Target $Target -Property "ACE[$ruleIndex]" -Scenario (Format-Ace -AccessRule $rule)))
        $ruleIndex++
    }

    $kclRules = @($accessRules | Where-Object { Test-KeyCredentialWriteCapableAce -AccessRule $_ })
    for ($index = 0; $index -lt $kclRules.Count; $index++) {
        $Rows.Add((New-DiffRow -Source 'PowerShell' -Surface 'ACL risk view' -Target $Target -Property "KeyCredentialLinkWriteCapableACE[$index]" -Scenario (Format-Ace -AccessRule $kclRules[$index])))
    }
}

function New-LdapConnection {
    param([Parameter(Mandatory = $true)][string]$ServerName)

    Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
    $connection = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList $ServerName
    $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    $connection.SessionOptions.Signing = $true
    $connection.SessionOptions.Sealing = $true
    $connection.Bind()
    return $connection
}

function Convert-LdapValueToDisplay {
    param(
        [Parameter(Mandatory = $true)][string]$AttributeName,
        [AllowNull()]$Value
    )

    if ($null -eq $Value) {
        return '<not set>'
    }
    if ($Value -is [byte[]]) {
        if ($AttributeName -ieq 'objectGUID' -and $Value.Length -eq 16) {
            return (New-Object -TypeName System.Guid -ArgumentList (, $Value)).ToString()
        }
        if ($AttributeName -ieq 'objectSid') {
            try {
                return ([System.Security.Principal.SecurityIdentifier]::new([byte[]]$Value, 0)).Value
            }
            catch {
                return (ConvertTo-DisplayValue -Value $Value)
            }
        }
        if ($AttributeName -ieq 'nTSecurityDescriptor') {
            return "bytes=$($Value.Length)"
        }
        return (ConvertTo-DisplayValue -Value $Value)
    }
    return (ConvertTo-DisplayValue -Value $Value)
}

function Add-LdapRows {
    param(
        [System.Collections.Generic.List[object]]$Rows,
        [Parameter(Mandatory = $true)]$Connection,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$DistinguishedName
    )

    $attributes = [string[]]@(
        'objectClass',
        'distinguishedName',
        'name',
        'objectGUID',
        'objectSid',
        'adminDescription',
        'description',
        'sAMAccountName',
        'userPrincipalName',
        'userAccountControl',
        'whenCreated',
        'whenChanged',
        'msDS-KeyCredentialLink',
        'nTSecurityDescriptor'
    )
    $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
        $DistinguishedName,
        '(objectClass=*)',
        [System.DirectoryServices.Protocols.SearchScope]::Base,
        $attributes
    )
    try {
        $mask = [System.DirectoryServices.Protocols.SecurityMasks]::Owner -bor [System.DirectoryServices.Protocols.SecurityMasks]::Dacl
        $request.Controls.Add((New-Object -TypeName System.DirectoryServices.Protocols.SecurityDescriptorFlagControl -ArgumentList $mask)) | Out-Null
    }
    catch {
        Write-Verbose "LDAP security descriptor control could not be added: $($_.Exception.Message)"
    }

    try {
        $response = $Connection.SendRequest($request)
    }
    catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        if ($_.Exception.Response.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::NoSuchObject) {
            return
        }
        throw
    }

    if ($response.Entries.Count -eq 0) {
        return
    }

    $entry = $response.Entries[0]
    foreach ($attributeName in $attributes) {
        $attribute = $entry.Attributes[$attributeName]
        if ($null -eq $attribute) {
            continue
        }
        $values = New-Object 'System.Collections.Generic.List[string]'
        for ($index = 0; $index -lt $attribute.Count; $index++) {
            $values.Add((Convert-LdapValueToDisplay -AttributeName $attributeName -Value $attribute[$index]))
        }
        $Rows.Add((New-DiffRow -Source 'LDAP' -Surface 'LDAP attributes' -Target $Target -Property $attributeName -Scenario (($values.ToArray()) -join '; ')))
    }
}

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}

$domainDn = [string]$domain.DistinguishedName
$rootOuDn = "OU=$script:RootOuName,$domainDn"
$scenarioOuDn = "OU=$ScenarioOuName,$rootOuDn"
$sampleUser = Get-ScenarioUserBySamOrNull -SamAccountName $SampleSamAccountName
$controlUser = Get-ScenarioUserBySamOrNull -SamAccountName $ControlSamAccountName
$scenarioOu = Get-AdObjectOrNull -DistinguishedName $scenarioOuDn -Properties @('adminDescription', 'description', 'name', 'objectGUID', 'whenChanged', 'whenCreated')

$rows = New-Object 'System.Collections.Generic.List[object]'
Add-AdObjectRows -Rows $rows -Target "OU:$scenarioOuDn" -Object $scenarioOu -Properties @('DistinguishedName', 'Name', 'ObjectGUID', 'adminDescription', 'description', 'whenCreated', 'whenChanged')
if ($null -ne $scenarioOu) {
    Add-AclRows -Rows $rows -Target "OU:$scenarioOuDn" -DistinguishedName $scenarioOuDn
}

foreach ($userSpec in @(
    @{ Label = "User:$SampleSamAccountName"; User = $sampleUser },
    @{ Label = "User:$ControlSamAccountName"; User = $controlUser }
)) {
    $user = $userSpec.User
    if ($null -eq $user) {
        continue
    }
    Add-AdObjectRows -Rows $rows -Target ([string]$userSpec.Label) -Object $user -Properties @('DistinguishedName', 'Name', 'ObjectGUID', 'SamAccountName', 'UserPrincipalName', 'Enabled', 'userAccountControl', 'adminDescription', 'Department', 'Description', 'DisplayName', 'whenCreated', 'whenChanged')
    Add-KeyCredentialRows -Rows $rows -Target ([string]$userSpec.Label) -User $user
    Add-AclRows -Rows $rows -Target ([string]$userSpec.Label) -DistinguishedName ([string]$user.DistinguishedName)
}

$ldapServer = if ($AdServerParameters.ContainsKey('Server')) { [string]$AdServerParameters['Server'] } else { [string]$domain.PDCEmulator }
$ldapConnection = $null
try {
    $ldapConnection = New-LdapConnection -ServerName $ldapServer
    if ($null -ne $scenarioOu) {
        Add-LdapRows -Rows $rows -Connection $ldapConnection -Target "OU:$scenarioOuDn" -DistinguishedName $scenarioOuDn
    }
    foreach ($userSpec in @(
        @{ Label = "User:$SampleSamAccountName"; User = $sampleUser },
        @{ Label = "User:$ControlSamAccountName"; User = $controlUser }
    )) {
        if ($null -ne $userSpec.User) {
            Add-LdapRows -Rows $rows -Connection $ldapConnection -Target ([string]$userSpec.Label) -DistinguishedName ([string]$userSpec.User.DistinguishedName)
        }
    }
}
finally {
    if ($null -ne $ldapConnection) {
        $ldapConnection.Dispose()
    }
}

$resultRows = @($rows.ToArray() | Sort-Object Source, Target, Surface, Property)
if ($PassThru) {
    return $resultRows
}

if ($resultRows.Count -eq 0) {
    Write-Host "No differences from Baseline 06 were found for $script:ScenarioName."
    return
}

$resultRows | Format-Table -AutoSize
