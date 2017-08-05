#Requires -Version 4

[CmdletBinding()]
param (
	
	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]$ProjectName = 'PowerLab',
	
	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[ValidateScript({ Test-Path -Path $_ -PathType Container })]
	[string]$ModulesPath = "$PSScriptRoot\$ProjectName",
	
	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]$ConfigFilePath = "$ModulesPath\configuration.xml",

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]$HostServerCredentialFilePath = "$ModulesPath\HostServerCred.xml"
	
)

try {
	
	#region Create a new blank configuration file
	if (-not (Test-Path -Path $ConfigFilePath -PathType Leaf))
	{
		[System.XML.XMLDocument]$xmlDoc = New-Object System.XML.XMLDocument
		[System.XML.XMLElement]$xmlRoot = $xmlDoc.CreateElement($ProjectName)
		$null = $xmlDoc.AppendChild($xmlRoot)
		$xmlDoc.Save($ConfigFilePath)
	}
	else
	{
		Write-Verbose -Message 'Existing configuration file found. Using that one.'
	}
	##TODO: Validate XML against XSD
	#endregion
	
	#region Save the host server credential file
	if (-not (Test-Path -Path $HostServerCredentialFilePath -PathType Leaf))
	{
		$HostServerCred = Get-Credential -Message 'Enter the username and password to connect to the host server'
		$HostServerCred | Export-CliXml $HostServerCredentialFilePath
	}
	#endregion
	
	#region Install modules
	$userModulePath = $env:PSModulePath.Split(';') | where { $PSItem -like "*$env:HOMEPATH*" }
	Copy-Item -Path $ModulesPath -Destination $userModulePath -Recurse -Force
	#endregion
	
	Import-Module PowerLab
}
catch
{
	Write-Error  "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
}