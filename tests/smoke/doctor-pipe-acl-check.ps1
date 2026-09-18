$ErrorActionPreference = 'Stop'
$doctorPath = [IO.Path]::Combine($PSScriptRoot, '..', '..', 'scripts', 'doctor.ps1')
$parseErrors = @()
$ast = [System.Management.Automation.Language.Parser]::ParseFile($doctorPath, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw $parseErrors[0] }
$names = @($ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true) | ForEach-Object { [string]$_.Name })

if ($names -contains 'Get-PipeAclCheck') {
    throw 'obsolete provider-based named-pipe ACL checker is still present'
}
foreach ($required in @('Get-AuthenticatedPipeAclStatus', 'Get-PipeAclStatusChecks')) {
    if ($names -notcontains $required) { throw "authenticated status checker missing: $required" }
}

$source = [IO.File]::ReadAllText($doctorPath)
foreach ($required in @(
        'UseProxy = $false', 'AllowAutoRedirect = $false', 'ResponseHeadersRead',
        'text/event-stream', 'Mcp-Name', "'status'", 'BridgeInstallationContextCandidateRootsIncomplete',
        '$candidateRoots | Where-Object', '$candidateRootArguments.Count -eq 3',
        '$doctorTransportServeHost = [string]$installationContext.serveHost',
        '$selectionArguments.InstallationContext = $InstallationContext',
        'Get-BridgeServicePairInspection @inspectionArguments'
    )) {
    if (-not $source.Contains($required)) { throw "bounded status-only transport invariant missing: $required" }
}
'PASS: pipe ACL doctor consumes bounded authenticated status observation only'
