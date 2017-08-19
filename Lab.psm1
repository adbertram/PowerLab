#Requires -RunAsAdministrator

#region Configuration
Set-StrictMode -Version Latest

$configFilePath = "$PSScriptRoot\LabConfiguration.psd1"
$script:LabConfiguration = Import-PowerShellDataFile -Path $configFilePath

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

		## Create the domain controller
		New-ActiveDirectoryForest
		
		# region Create the member servers
		foreach ($type in $($script:LabConfiguration.VirtualMachines).where($_.Type -ne 'Domain Controller').Type)
		{
			& "New-$TypeServer"
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
		[ValidateScript({ TestIsIsoNameValid $_ })]
		[string]$Name
		
	)
	$ErrorActionPreference = 'Stop'
	$isoFileName = (@($script:LabConfiguration.ISOs).where({ $_.Name -eq $Name })).FileName
	
	$convertParams = @{
		LocalFilePath = $script:LabConfiguration.IsoFolderPath
		ComputerName = $script:LabConfiguration.HostServer.Name
	}
	$uncIsoFolderPath = ConvertToUncPath @convertParams
	Get-ChildItem -Path $uncIsoFolderPath -Filter $isoFileName

}
function New-ActiveDirectoryForest
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		
	)

	## Build the VM
	$vm = New-LabVirtualMachine -ServerType 'Domain Controller' -PassThru

	## Grab config values from file
	$forestConfiguration = $script:LabConfiguration.ActiveDirectoryConfiguration
	$forestParams = @{
		DomainName = $forestConfiguration.DomainName
		DomainMode = $forestConfiguration.DomainMode
		ForestMode = $forestConfiguration.ForestMode
		Confirm = $false
		SafeModeAdministratorPassword = (ConvertTo-SecureString -AsPlainText $forestConfiguration.SafeModeAdministratorPassword -Force)
	}
	
	## Build the forest
	Install-ADDSForest @forestParams

	# Install-ADDSDomainController -DomainName test.local -Confirm:$false -InstallDns -SafeModeAdministratorPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force)
	
}
function New-SqlServer
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	()

	## Build the VM
	$vm = New-LabVirtualMachine -ServerType 'SQL' -PassThru
	Install-SqlServer -ComputerName $vm.Name
	
}
function New-WebServer
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	()

	## Build the VM
	$vm = New-LabVirtualMachine -ServerType 'Web' -PassThru
	Install-IIS -ComputerName $vm.Name
	
}
function Install-IIS
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName
	)

	$null = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Install-WindowsFeature -Name Web-Server }
	
}
function Install-SqlServer
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName
	)

	$uncProjectFolder = ConvertToUncPath -LocalFilePath $script:LabConfiguration.ProjectRootFolder -ComputerName $script:LabConfiguration.HostServer.Name
	$copiedConfigFile = Copy-Item -Path "$PSScriptRoot\SqlServer.ini" -Destination $uncProjectFolder -PassThru

	$invokeParams = @{
		ComputerName = $ComputerName
		Command = '{0} /CONFIGURATIONFILE={1}\SqlServer.ini' -f $script:LabConfiguration.SQLServerInstallerPath,$script:LabConfiguration.ProjectRootFolder
	}

	InvokeProgram @invokeParams
	
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
		[string]$ServerType,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$PassThru
	)

	if ($PSBoundParameters.ContainsKey('ServerType'))
	{
		$whereFilter = [scriptblock]::Create("`$_.Type -eq $ServerType")	
	} else {
		$whereFilter = { '*' }
	}

	$name = GetNextLabVmName -Type $ServerType

	## Create the VM
	$vmParams = @{
		ComputerName = $script:LabConfiguration.HostServer.Name
		Name = $name
		Path = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VMConfig.Path
		MemoryStartupBytes = $script:LabConfiguration.VmConfig.StartupMemory
		Switch = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VirtualSwitch.Name
		Generation = $script:LabConfiguration.VmConfig.Generation
		PassThru = $true
	}
	$vm = New-VM @vmParams

	## Create the VHD and install Windows on the VM
	$vm | AddOperatingSystem -OperatingSystem $_.OS
	
	if ($PassThru.IsPresent) {
		$vm
	}
	
}
function TestIsIsoNameValid
{
	[OutputType([bool])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Name
	)

	if ($Name -notin $script:LabConfiguration.ISOs.Name) {
		throw "The ISO with label '$Name' could not be found."
	} else {
		$true
	}
	
}
function AddOperatingSystem
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory,ValueFromPipeline)]
		[ValidateNotNullOrEmpty()]
		[Microsoft.HyperV.PowerShell.VirtualMachine]$InputObject,
	
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ TestIsIsoNameValid $_ })]
		[string]$OperatingSystem
		
	)

	$ErrorActionPreference = 'Stop'
	try
	{	
		$vhdName = "$($InputObject.Name).$($script:LabConfiguration.DefaultVHDConfig.Type)"
		Write-Verbose -Message "VHD name is [$($vhdName)]"
		$vhd = New-LabgVhd -Name $vhdName -OperatingSystem $OperatingSystem
		$InputObject | Add-VMHardDiskDrive -ComputerName $script:LabConfiguration.HostServer.Name -Path $vhd.ImagePath
		
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
function ConvertToVirtualDisk
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
			Copy-Item -Path "$PSScriptRoot\Convert-WindowsImage.ps1" -Destination $script:LabConfiguration.ProjectRootFolder -Force
			
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
				ArgumentList = (Join-Path -Path $script:LabConfiguration.ProjectRootFolder -ChilPath './Convert-WindowsImage.ps1'),$IsoFilePath,$SizeBytes,$Edition,$VhdFormat,$VhdPath,$Sizing,$VHDPartitionStyle,$AnswerFilePath
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
				ConvertToVirtualDisk @cvtParams
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
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Name
	
	)
	try
	{
		$defaultVhdPath = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Path

		$icmParams = @{
			ComputerName = $script:LabConfiguration.HostServer.Name
			ScriptBlock = { Get-ChildItem -Path $args[0] -File | foreach { Get-VHD -Path $_.FullName } }
			ArgumentList = $defaultVhdPath
		}
		Invoke-Command @icmParams
	}
	catch
	{
		$PSCmdlet.ThrowTerminatingError($_)
	}
}
function Get-LabVm
{
	[CmdletBinding()]
	param
	(
		[Parameter(ParameterSetName = 'Name')]
		[ValidateNotNullOrEmpty()]
		[string]$Name,

		[Parameter(ParameterSetName = 'Type')]
		[ValidateNotNullOrEmpty()]
		[string]$Type
	
	)
	$ErrorActionPreference = 'Stop'

	$nameMatch = $script:LabConfiguration.VirtualMachines.BaseName -join '|'
	if ($PSBoundParameters.ContainsKey('Name'))
	{
		$nameMatch = $Name
	} elseif ($PSBoundParameters.ContainsKey('Type')) {
		$nameMatch = 'DC'
	}

	try {
		$icmParams = @{
			ComputerName = $script:LabConfiguration.HostServer.Name
			ScriptBlock = { $name = $args[0]; @(Get-VM).where({ $_.Name -match $name }) }
			ArgumentList = $nameMatch
		}
		Invoke-Command @icmParams
	}
	catch
	{
		if ($_.Exception.Message -notmatch 'Hyper-V was unable to find a virtual machine with name') {
			$PSCmdlet.ThrowTerminatingError($_)
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
				Write-Verbose -Message "The lab switch [$($Name)] already exists."	
			}
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}
function ConvertToUncPath
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
function InvokeProgram
{
	[OutputType('void')]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Command,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[pscredential]$Credential
	)
	
	$wmiParams = @{
		ComputerName = $ComputerName
		Class = 'Win32_Process'
		Name = 'Create'
		Args = $Command
	}

	if ($PSBoundParameters.ContainsKey('Credential'))
	{
		$wmiParams.Credential = $Credential
	}
	$process = Invoke-WmiMethod @wmiParams
	if ($process.ReturnValue -ne 0)
	{
		throw "Process failed with exit code [$($process.ReturnValue)]"
	}
}
function GetNextLabVmName
{
	[OutputType('string')]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Type
	)

	$highNumberVm = Get-LabVm -Type $Type | Sort-Object -Descending | Select-Object -First 1
	if (-not $highNumberVm -or ($highNum = $highNumberVm -replace '[a-z][A-Z]+')) {
		$highNum = 1
	}
	if (-not ($types = @($script:LabConfiguration.VirtualMachines).where({$_.Type -eq $Type}))) {
		throw "Unrecognize VM type: [$($Type)]"
	}
	$baseName = $types.BaseName
	
	'{0}{1}' -f $baseName,$highNum
}

function Test-lab
{
	[OutputType('bool')]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		
	)

	$ErrorActionPreference = 'Stop'

	$uncProjectRoot = ConvertToUncPath -LocalFilePath $script:LabConfiguration.ProjectRootFolder -ComputerName $script:LabConfiguration.HostServer.Name
	$isoRoot = ConvertToUncPath -LocalFilePath $script:LabConfiguration.IsoFolderPath -ComputerName $script:LabConfiguration.HostServer.Name
	$vhdRoot = ConvertToUncPath -LocalFilePath $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Path -ComputerName $script:LabConfiguration.HostServer.Name
	$vmRoot = ConvertToUncPath -LocalFilePath $script:LabConfiguration.DefaultVirtualMachineConfiguration.VMConfig.Path -ComputerName $script:LabConfiguration.HostServer.Name

	$rules = @(
		@{
			Test = { Test-Connection -ComputerName $script:LabConfiguration.HostServer.Name -Quiet -Count 1 }
			FailMessage = 'They Hyper-V server could not be contacted.'
		}
		@{
			Test = { Test-Path -Path $uncProjectRoot -PathType Container }
			FailMessage = 'The ProjecRootFolder in Lab Configuration could not be found.'
		}
		@{
			Test = { Test-Path -Path $isoRoot -PathType Container }
			FailMessage = 'The IsoFolderPath in Lab Configuration could not be found.'
		}
		@{
			Test = { Test-Path -Path $vhdRoot -PathType Container }
			FailMessage = 'The default VHD path in Lab Configuration could not be found.'
		}
		@{
			Test = { Test-Path -Path $vmRoot -PathType Container }
			FailMessage = 'The default VM path in Lab Configuration could not be found.'
		}
		@{
			Test = { 
				if ($failures = @($script:LabConfiguration.ISOs).where({ -not (Test-Path -Path "$isoRoot\$($_.FileName)" -PathType Leaf)})) {
					$false
				} else {
					$true
				}
			}
			FailMessage = 'One or more ISOs specified in the ISOs section of Lab Configuration could not be found.'
		}
	)

	try {
		foreach ($rule in $rules) {
			if (-not (& $rule.Test)) {
				throw $rule.FailMessage
			}
		}
		$true
	} catch {
		$PSCmdlet.ThrowTerminatingError($_)
	}
	
}