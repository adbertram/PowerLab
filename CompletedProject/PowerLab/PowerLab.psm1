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
		}
		catch
		{
			Write-Error $_.Exception.Message
			$false
		}
	}
}

## Automate the Boring Stuff Additions
###################################################################################################################

$configFilePath = "$PSScriptRoot\LabConfiguration.psd1"
$script:LabConfiguration = Import-PowerShellDataFile -Path $configFilePath

function Get-LabIso
{
	[OutputType('System.IO.FileInfo')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ Test-IsOsValid $_ })]
		[string]$OperatingSystem
		
	)
	$ErrorActionPreference = 'Stop'
	$isoName = @($script:LabConfiguration.ISOs).where({ $_.OS -eq $OperatingSystem })
	
	Get-ChildItem -Path $script:LabConfiguration.IsoFolderPath -Filter $isoName

}

function New-ActiveDirectoryForest
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		
	)

	## Grab config values from file
	$forestConfiguration = $script:LabConfiguration
	New-LabVirtualMachine

	New-ActiveDirectoryForest
	
}

function New-SqlServer
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		
	)
	
}

function New-WebServer
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		
	)
	
}

function Install-IIS
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		
	)
	
}

function Install-SqlServer
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		
	)
	
}

function New-LabVirtualMachine
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('SQL','Web','Domain Controller')]
		[string]$ServerType
	)

	if ($PSBoundParameters.ContainsKey('ServerType'))
	{
		$whereFilter = [scriptblock]::Create("`$_.Type -eq $ServerType")	
	} else {
		$whereFilter = { '*' }
	}

	@($script:LabConfiguration.VirtualMachines).where($whereFilter).foreach({
		## Create the VM
		$vmParams = @{
			ComputerName = $script:LabConfiguration.HostServer.Name
			Name = $_.Name
			Path = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VMConfig.Path
			MemoryStartupBytes = $script:LabConfiguration.VmConfig.StartupMemory
			Switch = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VirtualSwitch.Name
			Generation = $script:LabConfiguration.VmConfig.Generation
			PassThru = $true
		}
		$vm = New-VM @vmParams

		## Create the VHD and install Windows on the VM
		$vm | Add-OperatingSystem -OperatingSystem $_.OS
		
	})
	
}

function Test-IsOsValid
{
	[OutputType([bool])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$OperatingSystem
	)

	if ($OperatingSystem -notin $script:LabConfiguration.ISOs.OS) {
		throw "The operating system '$OperatingSystem' is not supported."
	} else {
		$true
	}
	
}

function Add-OperatingSystem
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory,ValueFromPipeline)]
		[ValidateNotNullOrEmpty()]
		[Microsoft.HyperV.PowerShell.VirtualMachine]$InputObject,
	
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ Test-IsOsValid $_ })]
		[string]$OperatingSystem
		
	)

	$ErrorActionPreference = 'Stop'
	try
	{	
		$vhdName = "$($InputObject.Name).$((Get-PlDefaultVHDConfig).Type)"
		Write-Verbose -Message "VHD name is [$($vhdName)]"
		if (Test-PlVhd -Name $vhdName)
		{
			throw "There is already a VHD called [$($vhdName)]"	
		}
		$vhd = New-PlVhd -Name $vhdName -OperatingSystem $OperatingSystem
		$InputObject | Add-VMHardDiskDrive -ComputerName $hostserver.Name -Path $vhd.ImagePath
		
		$bootOrder = ($InputObject | Get-VMFirmware).Bootorder
		if ($bootOrder[0].BootType -ne 'Drive')
		{
			$InputObject | Set-VMFirmware -FirstBootDevice $InputObject.HardDrives[0]
		}
	}
	catch
	{
		Write-Error $_.Exception.Message
	}
}

function ConvertTo-VirtualDisk
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('\.vhdx?$')]
		[string]$VhdPath,
		
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$IsoFilePath,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$AnswerFilePath,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('Dynamic', 'Fixed')]
		[string]$Sizing = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Sizing,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Edition = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.OSEdition,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(512MB, 64TB)]
		[Uint64]$SizeBytes = (Invoke-Expression $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Size),
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('VHD', 'VHDX')]
		[string]$VhdFormat = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Type,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$VHDPartitionStyle = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.PartitionStyle,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$PassThru
		
	)
	process
	{
		try
		{
			$convertFilePath = $script:LabConfiguration.VHDConversionScriptPath
			
			$sb = {
				. $args[0]
				$convertParams = @{
					SourcePath = $args[1]
					SizeBytes = $args[2]
					Edition = $args[3]
					VHDFormat = $args[4]
					VHDPath = $args[5]
					VHDType = $args[6]
					VHDPartitionStyle = $args[7]
				}
				if ($args[8]) {
					$convertParams.UnattendPath = $args[8]
				}
				Convert-WindowsImage @convertParams
			}

			$icmParams = @{
				ComputerName = $script:LabConfiguration.HostServer.Name
				ScriptBlock = $sb
				ArgumentList = $convertFilePath,$IsoFilePath,$SizeBytes,$Edition,$VhdFormat,$VhdPath,$Sizing,$VHDPartitionStyle,$AnswerFilePath
			}
			$result = Invoke-Command @icmParams
			if ($PassThru.IsPresent) {
				$result
			}
		}
		catch
		{
			Write-Error -Message $_.Exception.Message
		}
	}
}

function New-LabVhd
{
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param
	(
		
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('\.vhdx?$')]
		[string]$Name,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(512MB, 1TB)]
		[int64]$Size = (Invoke-Expression $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Size),
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Path = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Path,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('Dynamic','Fixed')]
		[string]$Sizing = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Sizing,
	
		[Parameter(Mandatory,ParameterSetName = 'OSInstall')]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ Test-IsValidOs $_ })]
		[string]$OperatingSystem,
	
		[Parameter(ParameterSetName = 'OSInstall')]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			if (-not (Test-Path -Path $_ -PathType Leaf)) {
				throw "The autounattend file $($_) could not be found."
			} else {
				$true
			}
		})]
		[string]$UnattendedXmlPath
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{	
			$sb = {
				if (-not (Test-Path -Path $using:Path -PathType Container))
				{
					$null = mkdir $using:Path	
				}
			}
			Invoke-Command -ComputerName $script:LabConfiguration.HostServer.Name -ScriptBlock $sb
			
			$params = @{
				'SizeBytes' = $Size
			}
			if ($PSBoundParameters.ContainsKey('OperatingSystem'))
			{
				$cvtParams = $params + @{
					IsoFilePath = $script:LabConfiguration.ISOs.where({ $_.OS -eq $OperatingSystem })
					VhdPath = "$Path\$Name"
					VhdFormat = ([system.io.path]::GetExtension($Name) -replace '^.')
					Sizing = $Sizing
					PassThru = $true
				}
				if ($PSBoundParameters.ContainsKey('UnattendedXmlPath')) {
					$cvtParams.AnswerFilePath = $UnattendedXmlPath
				}
				ConvertTo-VirtualDisk @cvtParams
			}
			else
			{
				$params.ComputerName = $script:LabConfiguration.HostServer.Name
				$params.Path = "$Path\$Name.$Type"
				if ($Sizing -eq 'Dynamic')
				{
					$params.Dynamic = $true
				}
				elseif ($Sizing -eq 'Fixed')
				{
					$params.Fixed = $true
				}
				New-VHD @params
			}
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

