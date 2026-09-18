$ErrorActionPreference = 'Stop'
$doctorPath = Join-Path $PSScriptRoot '..\..\scripts\doctor.ps1'
$source = [IO.File]::ReadAllText($doctorPath)
$ast = [System.Management.Automation.Language.Parser]::ParseFile($doctorPath, [ref]$null, [ref]$null)
$ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-CheckResult'
}, $true) | ForEach-Object { Invoke-Expression $_.Extent.Text }
$start = $source.IndexOf('$checks = [Collections.Generic.List[object]]::new()')
$end = $source.IndexOf('$checks.Add((Get-ServiceCheck', $start)
$checkBlock = [scriptblock]::Create($source.Substring($start, $end - $start) + '; $checks[0]')
$script:policy = $null
$script:preference = 'true'
$script:completed = $true
$script:exitCode = 0
function Get-Command { return @{Source='fixture'} }
function Get-ItemPropertyValue { return $script:policy }
function Invoke-BoundedCommand {
    param($FilePath, $ArgumentList)
    switch ($ArgumentList[0]) {
        'status' { return @{completed=$true;exitCode=0;output='{"BackendState":"Running"}'} }
        'serve' { return @{completed=$true;exitCode=0;output='{"AppCaps":true}'} }
        'get' { return @{completed=$script:completed;exitCode=$script:exitCode;output=$script:preference} }
        default { throw 'Unexpected command' }
    }
}
function Assert-TailscaleStatus {
    param($Expected)
    $actual = & $checkBlock
    if ($actual.status -ne $Expected) { throw "Expected $Expected; got $($actual.status): $($actual.detail)" }
}
Assert-TailscaleStatus pass
$script:preference = 'false'
Assert-TailscaleStatus pass
$script:preference = 'unknown'
Assert-TailscaleStatus warn
$script:preference = 'true'
$script:completed = $false
Assert-TailscaleStatus warn
$script:completed = $true
$script:exitCode = 1
Assert-TailscaleStatus warn
foreach ($policy in @('always', 'never')) {
    $script:policy = $policy
    Assert-TailscaleStatus pass
}
'PASS: CLI preferences, invalid output, timeout, command failure, policy fallback'
