#requires -Version 5 -RunAsAdministrator

$repoZipFile = "$PSScriptRoot\AutomateTheBoringStuffWithPowerShell.zip"
Invoke-WebRequest -Uri 'https://github.com/adbertram/AutomateTheBoringStuffWithPowerShell/archive/master.zip' -OutFile $repoZipFile

$labModulePath = 'C:\Program Files\WindowsPowerShell\Modules'
$labRepoTempPath = "$env:Temp\AutomateTheBoringStuffWithPowerShell-master"
Expand-Archive -Path $repoZipFile -DestinationPath ($labRepoTempPath | Split-Path -Parent) -Force

"$env:Temp\Lab","$labModulePath\Lab",$repoZipFile | foreach {
	Remove-Item -Path $_ -ErrorAction Ignore -Recurse
}

$labModuleFolder = Rename-Item -Path $labRepoTempPath -NewName 'Lab' -PassThru -Force
Move-Item -Path $labModuleFolder.FullName -Destination $labModulePath -Force

& "$PSScriptRoot\PrerequisiteSetup.ps1"