$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.ServiceProcess
$evidence=Join-Path $PSScriptRoot '..\..\.omo\evidence'
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $evidence 'power-hotfix-apply.ps1'),[ref]$null,[ref]$null)
$rootAssignments=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -in @('$hotfixProgramRoot','$hotfixSourceRoot')})
if($rootAssignments.Count -ne 2) {throw 'HotfixRootsMissing'}
$rootAssignments | ForEach-Object {Invoke-Expression ($_.Extent.Text.Replace('$PSScriptRoot','$evidence'))}
$programBefore=$hotfixProgramRoot;$sourceBefore=$hotfixSourceRoot
. (Join-Path $evidence 'power-hotfix-source\scripts\service-runtime.ps1') -LibraryMode
if($hotfixProgramRoot -cne $programBefore -or $hotfixSourceRoot -cne $sourceBefore) {throw 'LibraryClobberedHotfixRoots'}
$call=$ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Invoke-BridgeServiceSwitchTransaction'},$true)[0]
$callback=($call.CommandElements | Where-Object {$_ -is [Management.Automation.Language.ScriptBlockExpressionAst]}).ScriptBlock.GetScriptBlock()
. (Join-Path $evidence 'power-hotfix-source\scripts\service-runtime-transaction.ps1')
$previous=[pscustomobject]@{serviceExecutable='old.exe';releaseId='old'}
$candidate=[pscustomobject]@{serviceExecutable='new.exe';releaseId='new';releaseRoot='candidate'}
$expectedCandidateId='new';$hotfixProgramRoot='fixture';$oldScripts='fixture';$serveHost='fixture.ts.net';$pointerBefore='old';$workerBefore='worker'
$definitions=@{gateway=@{name='Gateway';module='gateway'};privileged=@{name='Helper';module='helper'}}
function Stop-HotfixService {param($Name) $script:running[$Name]=$false}
function Start-Service {param($Name) $script:running[$Name]=$true}
function Get-Service {param($Name) $value=[pscustomobject]@{}; $value | Add-Member ScriptMethod WaitForStatus {param($status,$timeout)};return $value}
function Set-HotfixServicePath {
    param($Name,$ExpectedPath,$TargetPath)
    if ($script:running[$Name] -or $script:paths[$Name] -cne $ExpectedPath) {throw 'UnexpectedPathMutation'}
    $script:paths[$Name]=$TargetPath
}
function Get-CimInstance {param($ClassName,$Filter) $name=if($Filter -match 'Gateway'){'Gateway'}else{'Helper'};return [pscustomobject]@{PathName=$script:paths[$name]}}
function Assert-HotfixPair {
    param($Release,[switch]$Running)
    foreach($key in @('gateway','privileged')) {
        $d=$definitions[$key];$expected='"{0}" -I -B -m {1}' -f $Release.serviceExecutable,$d.module
        if($script:paths[$d.name] -cne $expected -or ($Running -and -not $script:running[$d.name])) {throw 'PairMismatch'}
    }
}
function Invoke-BridgeChildProcess {
    param($FilePath,$ArgumentList,$WorkingDirectory,$TimeoutSeconds)
    return [pscustomobject]@{exitCode=[int]$script:doctorFails;stdout='{"checks":[]}'}
}
function Get-HotfixWorkerHash {return 'worker'}
function Publish-BridgeActiveReleasePointer {param($ProgramRoot,$Release) $script:pointer=$Release.releaseId}
function Restore-BridgeActiveReleasePointerBody {param($ProgramRoot,$Body) $script:pointer=$Body}
function Resolve-BridgeServiceReleaseSelection {
    param($ProgramRoot)
    if($script:postCommitFails -and $script:pointer -eq 'new') {throw 'InjectedPostCommitFailure'}
    return [pscustomobject]@{releaseId=$script:pointer}
}
foreach($scenario in @('success','doctor-failure','post-commit-failure')) {
    $script:paths=@{Gateway='"old.exe" -I -B -m gateway';Helper='"old.exe" -I -B -m helper'}
    $script:running=@{Gateway=$true;Helper=$true};$script:pointer='old';$context=@{restoring=$false}
    $script:doctorFails=$scenario -eq 'doctor-failure';$script:postCommitFails=$scenario -eq 'post-commit-failure'
    $result=Invoke-BridgeServiceSwitchTransaction -PreviousState safe-pair -InvokeStep $callback
    if($scenario -eq 'success') {
        if($result.state -ne 'switched' -or $script:pointer -ne 'new') {throw ($result | ConvertTo-Json -Depth 4)}
        Assert-HotfixPair $candidate -Running
    } else {
        if($result.state -ne 'rolled-back' -or $result.rollbackFailures.Count -ne 0 -or $script:pointer -ne 'old') {throw ($result | ConvertTo-Json -Depth 4)}
        Assert-HotfixPair $previous -Running
    }
}
'PASS: library preserves roots, candidate callback success, doctor rollback, post-commit pointer rollback; no real service/power operations'

# 실제 빌드 CLI의 같은 인자를 사용하되 Apply만 제외해 관리자 실행 전 계약을 확인합니다.
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$buildPlan=Get-Content -LiteralPath (Join-Path $evidence 'power-hotfix-build-plan.json') -Raw | ConvertFrom-Json
$hotfixSourceRoot=$buildPlan.sourceRoot;$hotfixProgramRoot=$buildPlan.programRoot;$expectedCandidateId=$buildPlan.sourceDigest
$buildAssignment=$ast.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$buildArguments'},$true)[0]
Invoke-Expression $buildAssignment.Extent.Text
$readOnlyArguments=@($buildArguments | Where-Object {$_ -cne '-Apply'})
$buildOutput=@(& (Join-Path $PSHOME 'powershell.exe') @readOnlyArguments)
if($LASTEXITCODE -ne 0) {throw 'ActualBuildCliFailed'}
$actualPlan=($buildOutput -join [Environment]::NewLine) | ConvertFrom-Json
if($actualPlan.state -ne 'planned' -or $actualPlan.applied -or $actualPlan.sourceDigest -cne $expectedCandidateId -or $actualPlan.failureReasons.Count -ne 0) {throw 'ActualBuildCliPlanMismatch'}
'PASS: actual Windows PowerShell build CLI with production arguments except Apply'
