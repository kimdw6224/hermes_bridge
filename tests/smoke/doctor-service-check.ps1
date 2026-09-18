$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scripts', 'doctor.ps1')), [ref]$null, [ref]$null)
$ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -in @('New-CheckResult', 'Get-ServiceCheck')
}, $true) | ForEach-Object { Invoke-Expression $_.Extent.Text }
$script:queryText = [regex]::Unescape('\uC0C1\uD0DC : 4 RUNNING')
$script:configText = 'SERVICE_START_NAME : LocalSystem'
$script:recoveryText = 'RESET_PERIOD (in seconds) : 86400' + "`n" +
    ((5000,15000,60000 | ForEach-Object {
        [regex]::Unescape('\uB2E4\uC2DC \uC2DC\uC791 -- \uC9C0\uC5F0 = ') + $_ + [regex]::Unescape('\uBC00\uB9AC\uCD08.')
    }) -join "`n")
$script:exitCodes = @{query=0;qc=0;qfailure=0}
function Invoke-BoundedCommand {
    param($FilePath, $ArgumentList)
    $output = switch ($ArgumentList[0]) {
        'query' { $script:queryText }
        'qc' { $script:configText }
        'qfailure' { $script:recoveryText }
    }
    return @{completed=$true;exitCode=$script:exitCodes[$ArgumentList[0]];output=$output}
}
function Assert-ServiceStatus {
    param($Expected)
    $actual = Get-ServiceCheck -Id 'fixture' -Name 'fixture' -ExpectedAccount 'LocalSystem'
    if ($actual.status -ne $Expected) { throw "Expected $Expected; got $($actual.status): $($actual.detail)" }
}
Assert-ServiceStatus pass
$script:queryText = 'STATE : 4 RUNNING'
$script:recoveryText = "RESET_PERIOD (in seconds) : 86400`nRESTART -- Delay = 5000 milliseconds.`nRESTART -- Delay = 15000 milliseconds.`nRESTART -- Delay = 60000 milliseconds."
Assert-ServiceStatus pass
$script:queryText = 'STATE : 1 STOPPED'
Assert-ServiceStatus fail
$script:queryText = 'STATE : 4 RUNNING'
$script:configText = 'SERVICE_START_NAME : WrongAccount'
Assert-ServiceStatus fail
$script:configText = 'SERVICE_START_NAME : LocalSystem'
$script:recoveryText = $script:recoveryText.Replace('60000', '600000')
Assert-ServiceStatus fail
foreach ($command in @('query', 'qc', 'qfailure')) {
    $script:exitCodes[$command] = 5
    Assert-ServiceStatus warn
    $actual = Get-ServiceCheck -Id 'fixture' -Name 'fixture' -ExpectedAccount 'LocalSystem'
    if ($actual.detail -notmatch 'access denied' -or -not $actual.critical) { throw 'Access denial must remain critical and unverified' }
    $script:exitCodes[$command] = 1060
    Assert-ServiceStatus fail
    $actual = Get-ServiceCheck -Id 'fixture' -Name 'fixture' -ExpectedAccount 'LocalSystem'
    if ($actual.detail -ne 'service is not installed') { throw 'Missing service must be reported distinctly' }
    $script:exitCodes[$command] = 87
    Assert-ServiceStatus warn
    $actual = Get-ServiceCheck -Id 'fixture' -Name 'fixture' -ExpectedAccount 'LocalSystem'
    if ($actual.detail -match 'not installed') { throw 'Unexpected query failure is not proof of absence' }
    $script:exitCodes[$command] = 0
}
'PASS: Korean, English, stopped, wrong account, wrong recovery delay, denied/missing/unknown queries'
