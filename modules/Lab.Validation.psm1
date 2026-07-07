Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-LabValidationResult {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('Passed', 'Failed', 'Skipped')][string]$Status,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    return [pscustomobject]@{
        PSTypeName = 'ADLab.ValidationResult'
        Timestamp  = (Get-Date).ToString('o')
        Category   = $Category
        Name       = $Name
        Status     = $Status
        Expected   = $Expected
        Actual     = $Actual
        Message    = $Message
    }
}

function Test-LabExpectedValue {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [switch]$CaseSensitive
    )

    $matches = if ($CaseSensitive) { [string]$Expected -ceq [string]$Actual } else { [string]$Expected -ieq [string]$Actual }
    $status = if ($matches) { 'Passed' } else { 'Failed' }
    return New-LabValidationResult -Category $Category -Name $Name -Status $status -Expected $Expected -Actual $Actual
}

function Export-LabValidationResults {
    param(
        [Parameter(Mandatory = $true)][object[]]$Results,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $passed = @($Results | Where-Object Status -eq 'Passed').Count
    $failed = @($Results | Where-Object Status -eq 'Failed').Count
    $skipped = @($Results | Where-Object Status -eq 'Skipped').Count
    $document = [ordered]@{
        GeneratedAt = (Get-Date).ToString('o')
        Summary = [ordered]@{
            Total = $Results.Count
            Passed = $passed
            Failed = $failed
            Skipped = $skipped
        }
        Results = @($Results)
    }
    $document | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
    return [pscustomobject]@{
        Path = $Path
        Total = $Results.Count
        Passed = $passed
        Failed = $failed
        Skipped = $skipped
    }
}

function Get-LabAuditPolicyValue {
    param([Parameter(Mandatory = $true)][guid]$SubcategoryGuid)

    if ($null -eq ('ADLab.NativeAuditPolicy' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ADLab {
    [StructLayout(LayoutKind.Sequential)]
    public struct AuditPolicyInformation {
        public Guid AuditSubCategoryGuid;
        public UInt32 AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    public static class NativeAuditPolicy {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditQuerySystemPolicy(
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] Guid[] subCategoryGuids,
            UInt32 policyCount,
            out IntPtr auditPolicy);

        [DllImport("advapi32.dll")]
        private static extern void AuditFree(IntPtr buffer);

        public static UInt32 Query(Guid subCategoryGuid) {
            IntPtr buffer;
            if (!AuditQuerySystemPolicy(new Guid[] { subCategoryGuid }, 1, out buffer)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try {
                AuditPolicyInformation policy = (AuditPolicyInformation)Marshal.PtrToStructure(
                    buffer, typeof(AuditPolicyInformation));
                return policy.AuditingInformation;
            }
            finally {
                AuditFree(buffer);
            }
        }
    }
}
'@
    }

    $value = [ADLab.NativeAuditPolicy]::Query($SubcategoryGuid)
    return [pscustomobject]@{
        Value   = $value
        Success = (($value -band 1) -eq 1)
        Failure = (($value -band 2) -eq 2)
    }
}

Export-ModuleMember -Function @(
    'Export-LabValidationResults',
    'Get-LabAuditPolicyValue',
    'New-LabValidationResult',
    'Test-LabExpectedValue'
)
