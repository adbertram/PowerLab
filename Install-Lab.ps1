#requires -Version 5 -RunAsAdministrator

$repoZipFile = "$PSScriptRoot\AutomateTheBoringStuffWithPowerShell.zip"
Invoke-WebRequest -Uri 'https://github.com/adbertram/AutomateTheBoringStuffWithPowerShell/archive/master.zip' -OutFile $repoZipFile

$labModulePath = 'C:\Program Files\WindowsPowerShell\Modules'
$labRepoTempPath = "$env:Temp\AutomateTheBoringStuffWithPowerShell-master"
Expand-Archive -Path $repoZipFile -DestinationPath ($labRepoTempPath | Split-Path -Parent) -Force

Remove-Item -Path "$env:Temp\Lab" -ErrorAction Ignore -Recurse
Remove-Item -Path "$labModulePath\Lab" -ErrorAction Ignore -Recurse

$labModuleFolder = Rename-Item -Path $labRepoTempPath -NewName 'Lab' -PassThru -Force
Move-Item -Path $labModuleFolder.FullName -Destination $labModulePath -Force

& "$PSScriptRoot\PrerequisiteSetup.ps1"