#Requires -Version 5.1

# Schema validation for a lab config file. This checks required sections,
# types, and internal contradictions. It does not require the shipped
# ad.lab.exceeds.test instance values.

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'config\LabConfig.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path $PSScriptRoot -Parent
$commonModule = Join-Path $repositoryRoot 'modules\Lab.Common.psm1'
Import-Module $commonModule -Force -ErrorAction Stop
$config = Import-LabConfig -Path $ConfigPath

[pscustomobject]@{
    Valid        = $true
    Kind         = 'Schema'
    ConfigPath   = (Resolve-Path -LiteralPath $ConfigPath).Path
    VMName       = [string]$config.Lab.VMName
    ComputerName = [string]$config.Lab.ComputerName
    DomainName   = [string]$config.Domain.DnsName
    SwitchName   = [string]$config.Network.SwitchName
}
