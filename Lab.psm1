#Requires -RunAsAdministrator

#region Configuration
Set-StrictMode -Version Latest

$configFilePath = "$PSScriptRoot\LabConfiguration.psd1"
$script:LabConfiguration = Import-PowerShellDataFile -Path $configFilePath

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

function New-Lab
{
	[CmdletBinding()]
	param (		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$WinRmCopy
	)
	try
	{		
		## Create the switch
		New-LabSwitch
		
		# region Create VMs
		foreach ($vm in $script:LabConfiguration.VirtualMachines)
		{
			New-LabVirtualMachine -Name $vm.Name -ServerType $vm.Type
		}
		#endregion
	}
	catch
	{
		Write-Error  "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
	}
}
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
		$vhdName = "$($InputObject.Name).$($script:LabConfiguration.DefaultVHDConfig.Type)"
		Write-Verbose -Message "VHD name is [$($vhdName)]"
		$vhd = New-LabgVhd -Name $vhdName -OperatingSystem $OperatingSystem
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
function Get-LabVhd
{
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param
	(
		[Parameter(ParameterSetName = 'Name')]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('\.vhdx?$')]
		[string]$Name,
		
		[Parameter(ParameterSetName = 'Path')]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('^\w:.+\.vhdx?$')]
		[string]$Path
	
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
		function ConvertTo-UncPath
		{	
			[CmdletBinding()]
			param (
				[Parameter(Mandatory)]
				[string]$LocalFilePath,
				
				[Parameter(Mandatory)]
				[string]$ComputerName
			)
			process
			{
				$RemoteFilePathDrive = ($LocalFilePath | Split-Path -Qualifier).TrimEnd(':')
				"\\$ComputerName\$RemoteFilePathDrive`$$($LocalFilePath | Split-Path -NoQualifier)"
			}
		}
	}
	process
	{
		try
		{
			if ($PSCmdlet.ParameterSetName -eq 'None')
			{
				$vhdsPath = ConvertTo-UncPath -LocalFilePath ($script:LabConfiguration.DefaultVHDConfig).Path -ComputerName $HostServer.Name
				Get-ChildItem -Path $vhdsPath -File | foreach {
					Get-VHD -Path $_.FullName -ComputerName $HostServer.Name
				}
			}
			else
			{
				$vhdsPath = ($script:LabConfiguration.DefaultVHDConfig).Path
				if ($PSBoundParameters.ContainsKey('Name'))
				{
					$Path = "$vhdsPath\$Name"
				}
				try
				{
					Get-Vhd -Path $Path -ComputerName $HostServer.Name
				}
				catch [System.Management.Automation.ActionPreferenceStopException]
				{
					
				}
				
			}
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}
function New-LabSwitch
{
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Name = $script:LabConfiguration.Environment.Switch.Name,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('Internal','External')]
		[string]$SwitchType	= $script:LabConfiguration.Environment.Switch.Type
		
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{
			if (-not (Get-LabSwitch | where { $_.Name -eq $Name }))
			{
				$sParams = @{
					'Name' = $Name
					'SwitchType' = $SwitchType
				}
				New-VMSwitch @sParams
			}
			else
			{
				Write-Verbose -Message "The PowerLab switch [$($Name)] already exists."	
			}
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

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
function Get-OperatingSystemAnswerFile
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
			$ansPath = $script:LabConfiguration.Configuration.Folders.SelectSingleNode("//Folder[@Name='UnattendXml' and @Location='HostServer']").Path
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