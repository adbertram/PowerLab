#Requires -RunAsAdministrator

function ConvertTo-UncPath
{
	<#
		.SYNOPSIS
			A simple function to convert a local file path and a computer name to a network UNC path.

		.PARAMETER LocalFilePath
			A file path ie. C:\Windows\somefile.txt

		.PARAMETER Computername
			One or more computers in which the file path exists on
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$LocalFilePath,
		
		[Parameter(Mandatory)]
		[string[]]$ComputerName
	)
	process
	{
		try
		{
			foreach ($Computer in $ComputerName)
			{
				$RemoteFilePathDrive = ($LocalFilePath | Split-Path -Qualifier).TrimEnd(':')
				"\\$Computer\$RemoteFilePathDrive`$$($LocalFilePath | Split-Path -NoQualifier)"
			}
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

function Get-PlDefaultVHDConfig
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
			(Get-PlConfigurationData).DefaultVHDConfig
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

function Get-PlDefaultVMConfig
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
			(Get-PlConfigurationData).DefaultVMConfig
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

function Get-PlIsoFile
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$OperatingSystem
		
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{
			$allowedOSes = (Get-PlConfigurationData).Configuration.ISOs.ISO.OS
			if ($OperatingSystem -notin $allowedOSes)
			{
				throw "The operating system [$($OperatingSystem)] is not configured. Use any of the following instead: $allowedOSes"
			}
			
			$isoName = (Get-PlConfigurationData).Configuration.ISOs.SelectSingleNode("//ISO[@OS='$OperatingSystem']").Name
			$isosPath = (Get-PlConfigurationData).Configuration.Folders.SelectSingleNode("//Folder[@Name='ISO' and @Location='HostServer']").Path
			$isoPath = "$isosPath\$isoName"
			$icmParams = @{
				'ComputerName' = $HostServer.Name
				'Credential' = $HostServer.Credential
				'ScriptBlock' = { Get-Item -Path $using:isoPath }
			}
			Invoke-Command @icmParams
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

function Get-PlAnswerFile
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$VMName
		
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{
			$ansPath = (Get-PlConfigurationData).Configuration.Folders.SelectSingleNode("//Folder[@Name='UnattendXml' and @Location='HostServer']").Path
			$icmParams = @{
				'ComputerName' = $HostServer.Name
				'Credential' = $HostServer.Credential
				'ScriptBlock' = { Get-Item -Path "$using:ansPath\$using:VMName.xml" }
			}
			Invoke-Command @icmParams
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

function Get-PlConfigurationData
{
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param
	(
		[Parameter(ParameterSetName = 'ConfigurationFolder')]
		[ValidateNotNullOrEmpty()]
		[string]$ConfigurationFolder,
		
		[Parameter(ParameterSetName = 'VM')]
		[ValidateNotNullOrEmpty()]
		[string[]]$VM,
		
		[Parameter(ParameterSetName = 'Domain')]
		[ValidateNotNullOrEmpty()]
		[switch]$Domain,
		
		[Parameter(ParameterSetName = 'HostServer')]
		[ValidateNotNullOrEmpty()]
		[switch]$HostServer
		
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{
			$xConfig = [xml](Get-Content -Path $ConfigFilePath)
			$xConfig = $xConfig.PowerLab
			if ($PSBoundParameters.ContainsKey('VM'))
			{
				$xConfig.VirtualMachines.VM | where { $_.Name -in $VM }
			}
			elseif ($PSBoundParameters.ContainsKey('ConfigurationFolder'))
			{
				$xConfig.Configuration.Folders.SelectSingleNode("//Folder[@Name='$ConfigurationFolder']")
			}
			elseif ($PSBoundParameters.ContainsKey('HostServer'))
			{
				$xConfig.HostServer
			}
			elseif ($Domain.IsPresent)
			{
				$xConfig.Domain
			}
			else
			{
				$xConfig
			}
			
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

function Get-PlVMConfiguration
{
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string[]]$VM
		
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{
			if ($PSBoundParameters.ContainsKey('VM'))
			{
				Get-PlConfigurationData -VM $VM
			}
			else
			{
				(Get-PlConfigurationData).VirtualMachines.VM
			}
			
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

function Get-PlConfigurationFolder
{
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Name
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{
			if ($PSBoundParameters.ContainsKey('Name'))
			{
				Get-PlConfigurationData -ConfigurationFolder $Name
			}
			else
			{
				(Get-PlConfigurationData).Configuration.Folders.SelectNodes("//Folder")
			}
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

function Get-InstalledSoftware
{
			<#
			.SYNOPSIS
				Retrieves a list of all software installed
			.EXAMPLE
				Get-InstalledSoftware
				
				This example retrieves all software installed on the local computer
			.PARAMETER Name
				The software title you'd like to limit the query to.
			.PARAMETER Guid
				The software GUID you'e like to limit the query to
			#>
	[CmdletBinding()]
	param (
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ Test-Connection -ComputerName $_ -Quiet -Count 1 })]
		[string[]]$ComputerName,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[pscredential]$Credential,
		
		[string]$Name,
		
		[ValidatePattern('\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')]
		[string]$Guid
	)
	process
	{
		try
		{
			$scriptBlock = {
				$UninstallKeys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
				New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
				$UninstallKeys += Get-ChildItem HKU: | where { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | foreach { "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
				if (-not $UninstallKeys)
				{
					Write-Warning -Message 'No software registry keys found'
				}
				else
				{
					foreach ($UninstallKey in $UninstallKeys)
					{
						$friendlyNames = @{
							'DisplayName' = 'Name'
							'DisplayVersion' = 'Version'
						}
						Write-Verbose -Message "Checking uninstall key [$($UninstallKey)]"
						if ($PSBoundParameters.ContainsKey('Name'))
						{
							$WhereBlock = { $_.GetValue('DisplayName') -like "$Name*" }
						}
						elseif ($PSBoundParameters.ContainsKey('GUID'))
						{
							$WhereBlock = { $_.PsChildName -eq $Guid }
						}
						else
						{
							$WhereBlock = { $_.GetValue('DisplayName') }
						}
						$SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | Where-Object $WhereBlock
						if (-not $SwKeys)
						{
							Write-Verbose -Message "No software keys in uninstall key $UninstallKey"
						}
						else
						{
							foreach ($SwKey in $SwKeys)
							{
								$output = @{ }
								foreach ($ValName in $SwKey.GetValueNames())
								{
									if ($ValName -ne 'Version')
									{
										$output.InstallLocation = ''
										if ($ValName -eq 'InstallLocation' -and ($SwKey.GetValue($ValName)) -and (@('C:', 'C:\Windows', 'C:\Windows\System32', 'C:\Windows\SysWOW64') -notcontains $SwKey.GetValue($ValName).TrimEnd('\')))
										{
											$output.InstallLocation = $SwKey.GetValue($ValName).TrimEnd('\')
										}
										[string]$ValData = $SwKey.GetValue($ValName)
										if ($friendlyNames[$ValName])
										{
											$output[$friendlyNames[$ValName]] = $ValData.Trim() ## Some registry values have trailing spaces.
										}
										else
										{
											$output[$ValName] = $ValData.Trim() ## Some registry values trailing spaces
										}
									}
								}
								$output.GUID = ''
								if ($SwKey.PSChildName -match '\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')
								{
									$output.GUID = $SwKey.PSChildName
								}
								New-Object �TypeName PSObject �Prop $output
							}
						}
					}
				}
			}
			if ($PSBoundParameters.ContainsKey('ComputerName'))
			{
				$icmParams = @{
					'ComputerName' = $ComputerName
					'ScriptBlock' = $scriptBlock
				}
				if ($PSBoundParameters.ContainsKey('Credential'))
				{
					$icmParams.Credential = $Credential
				}
				Invoke-Command @icmParams
			}
			else
			{
				& $scriptBlock
			}
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}