#Requires -RunAsAdministrator

#region Configuration
Set-StrictMode -Version Latest

$global:Project = [pscustomobject]@{ 'Name' = 'PowerLab' }

$global:ConfigFilePath = "$PSScriptRoot\configuration.xml"
$HostServerCredFile = "$PSScriptRoot\HostServerCred.xml"

$xConfig = [xml](Get-Content -Path $ConfigFilePath)
$xConfig = $xConfig.PowerLab

$global:HostServer = [pscustomobject]@{
	'Name' = $xConfig.HostServer.Name
	'Credential' = Import-Clixml -Path $HostServerCredFile
}

if ((cmdkey /list:($HostServer.Name)) -match '\* NONE \*')
{
	$credential = Get-Credential -Message "The credentials for $($HostServer.Name) were not found on the local machine. Please provide a username and password with access to the host."
	if (-not $credential)
	{
		throw 'No credential provided. You must specify a credential to connect to the host server'	
	}
	cmdkey /add:($HostServer.Name) /user:($credential.UserName) /pass:($credential.GetNetworkCredential().Password)
}

#endregion

function Invoke-PlAction
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[scriptblock]$ScriptBlock,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$AsJob
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try
		{
			if ($PSBoundParameters.ContainsKey('AsJob')) {
				$sjParams = @{
					'ScriptBlock' = $Scriptblock
				}
				if ($PSBoundParameters.ContainsKey('PassThru')) {
					Start-Job @sjParams
				}
				else
				{
					$null = Start-Job @sjParams
				}
			}
			else
			{
				& $ScriptBlock				
			}
		}
		catch
		{
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}

function New-PlHost
{
	[CmdletBinding()]
	param
	(
	
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{
			
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

function New-PowerLab
{
	[CmdletBinding()]
	param (		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$WinRmCopy
	)
	try
	{
		
		#region Install SQL Server Express
		
		
		#endregion
		
		#region Setup default database
		New-PlDatabase
		#endregion
#		
#		#region Install RSAT
#		if (Test-ClientOperatingSystem)
#		{
#			Install-RSAT
#		}
#		#endregion
#		
#		#region Ensure the Hyper-V Manager feature is enabled
#		## TODO
#		#endregion
#		
#		#region Create and save a host server credential to disk
#		if (-not (Test-PlHostServerCredential))
#		{
#			Save-PlHostServerCredential -Credential (Get-Credential -Message 'Enter a username and password to connect to the host server')
#		}
#		else
#		{
#			Write-Verbose -Message 'The host server credential file already exists.'
#		}
#		#endregion
#		
#		#region Setup workgroup WinRM connectivity
#		Set-WorkgroupConnectivity
#		#endregion
#		
#		#region Copy all required files to host server
#		$foldersToCopy = (Get-PlConfigurationData).SelectNodes("//Configuration/Folders/Folder[@ToCopyToHostServer='Yes']").Path
#		$rootDestPath = (Get-PlConfigurationFolder | where { $_.Location -eq 'HostServer' -and $_.Name -eq 'PowerLabRoot' }).Path
#		if ($WinRmCopy.IsPresent)
#		{
#			$session = New-PSSession -ComputerName $hostServer.Name -Credential $hostServer.Credential
#		}
#		foreach ($f in $foldersToCopy)
#		{
#			if ($WinRmCopy.IsPresent)
#			{
#				Send-FileOverWinRm -Path $f -Destination $rootDestPath -Session $session
#			}
#			else
#			{
#				$rootDestPath = ConvertTo-UncPath -ComputerName $hostServer.Name -LocalFilePath $rootDestPath
#				Write-Verbose -Message "Copying [$($f)] to [$($rootDestPath)]"
#				Copy-Item -Path $f -Destination $rootDestPath -Recurse -Container -Verbose
#			}
#		}
#		#endregion
#		
#		## Create the switch
#		New-PlSwitch
		
		#region Create VMs
#		foreach ($vm in (Get-PlVMConfiguration))
#		{
#			$params = @{}
#			if ($vm.UseDefaultConfig)
#			{
#				$params.Name = $vm.Name
#			}
#			else
#			{
#				##TODO	
#			}
#			if ($vm.InstallOS)
#			{
#				
#			}
#			New-PlVm @params
#		}
		#endregion
	}
	catch
	{
		Write-Error  "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
	}
	finally
	{
		if (Test-Path Variable:\session)
		{
			Remove-PSSession -Session $session
		}
	}
}

function Test-ClientOperatingSystem
{
	[CmdletBinding()]
	param
	(
		
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try
		{
			if ((Get-CimInstance -ClassName Win32_OperatingSystem).Caption -like '*Server*')
			{
				$false
			}
			else
			{
				$true	
			}
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

function Test-PlPowerLab
{
	[CmdletBinding()]
	param
	(
		
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try
		{
			#region Ensure all local folders exist
			$folders = Get-PlConfigurationFolder | where { $_.Required -eq 'Yes' }
			foreach ($f in $folders)
			{
				if (-not (Test-Path -Path $f.Path -PathType Container))
				{
					throw "The configuration folder [$($f.Name)] at [$($f.Path)] cannot be found."
				}
				else
				{
					Write-Verbose -Message "The folder [$($f.Name)] is good to go"	
				}
			}
			#endregion
			
			#region Ensure all appropriate unattend XML files are there
			$unattendXmlFolder = (Get-PlConfigurationFolder -Name UnattendXml).Path
			if (-not ($xmls = Get-ChildItem -Path $unattendXmlFolder))
			{
				throw "No unattended XML files found in [$($unattendXmlFolder)]"
			}
			else
			{
				$vmNames = (Get-PlVmConfiguration).Name
				$unattendVmNames = $xmls.BaseName | where { $_ -in $vmNames }
				if (diff $vmNames $unattendVmNames)
				{
					throw 'All VMs do not have corresponding auto unattend XML files'
				}
				else
				{
					Write-Verbose -Message 'Auto unattend XML files are good.'	
				}
				
			}
			#endregion
			
			#region Ensure all ISOs are available
			$requiredOSes = (Get-PlVMConfiguration).OS.Edition | Select -Unique
			$isoOSesDownloaded = (Get-PlConfigurationData).Configuration.ISOs.ISO.Name
			if (diff $requiredOSes $isoOSesDownloaded)
			{
				throw 'One or more ISOs are not downloaded for the operating systems to deploy'
			}
			else
			{
				Write-Verbose -Message 'All ISOs downloaded'
			}
			#endregion
			
			#region Ensure host server is online
			if (-not (Test-Connection -ComputerName (Get-PlHostServerConfiguration).Name -Quiet -Count 1))
			{
				throw "The host server [$((Get-PlHostServerConfiguration).Name)] is not available."	
			}
			#endregion
			
			#region Ensure RSAT is installed (if client OS)
			
			#endregion
			
			#region Ensure Hyper-V manager feature is enabled
			
			#endregion
			
			#region Ensure the host server credential exists
			$userModulePath = $env:PSModulePath.Split(';') | where { $PSItem -like "*$env:HOMEPATH*" }
			$plModulePath = "$userModulePath\PowerLab"
			if (-not (Test-Path -Path $plModulePath -PathType Leaf))
			{
				throw "The host server credential file does not exist in [$($plModulePath)]"
			}
			else
			{
				Write-Verbose -Message 'The host server credential file exists.'	
			}
			#endregion
			
			#region Ensure we can connect via WinRM to host server
			
			#endregion
			$true
		}
		catch
		{
			Write-Error $_.Exception.Message
			$false
		}
	}
}