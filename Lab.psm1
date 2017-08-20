#Requires -RunAsAdministrator

#region Configuration
Set-StrictMode -Version Latest

## Change this back to LabConfiguration.psd1
																				$configFilePath = "$PSScriptRoot\MyLabConfiguration.psd1"
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
	$vm = New-LabVm -ServerType 'Domain Controller' -PassThru

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
	$vm = New-LabVm -ServerType 'SQL' -PassThru
	Install-SqlServer -ComputerName $vm.Name
	
}
function New-WebServer
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	()

	## Build the VM
	$vm = New-LabVm -ServerType 'Web' -PassThru
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
function New-LabVm
{
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('SQL','Web','Domain Controller')]
		[string]$Type,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$PassThru
	)

	if ($PSBoundParameters.ContainsKey('Type'))
	{
		$whereFilter = [scriptblock]::Create("`$_.Type -eq $Type")
	} else {
		$whereFilter = { '*' }
	}

	$name = GetNextLabVmName -Type $Type

	## Create the VM
	$scriptBlock = {
		$vmParams = @{
			Name = $args[0]
			Path = $args[1]
			MemoryStartupBytes = $args[2]
			Switch = $args[3]
			Generation = $args[4]
			PassThru = $true
		}
		$vm = New-VM @vmParams
	}
	$argList = @(
		$name
		$script:LabConfiguration.DefaultVirtualMachineConfiguration.VMConfig.Path
		$script:LabConfiguration.DefaultVirtualMachineConfiguration.VMConfig.StartupMemory
		$script:LabConfiguration.DefaultVirtualMachineConfiguration.VirtualSwitch.Name
		$script:LabConfiguration.DefaultVirtualMachineConfiguration.VmConfig.Generation
	)
	$vm = InvokeHyperVCommand -Scriptblock $scriptBlock -ArgumentList $argList

	## Create the VHD and install Windows on the VM
	$os = @($script:LabConfiguration.VirtualMachines).where({$_.Type -eq $Type}).OS
	$vm | AddOperatingSystem -OperatingSystem $os
	
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
function TestIsOsNameValid
{
	[OutputType([bool])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Name
	)

	if (($Name -notin ($script:LabConfiguration.ISOs | Where-Object { $_.Type -eq 'OS' }).Name)) {
		throw "The operating system name '$Name' is not valid."
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
		[ValidateScript({ TestIsOsNameValid $_ })]
		[string]$OperatingSystem
		
	)

	$ErrorActionPreference = 'Stop'
	try
	{	
		$vhdName = "$($InputObject.Name).$($script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Type)"
		$vhd = New-LabVhd -Name $vhdName -OperatingSystem $OperatingSystem

		$invParams = @{
			Scriptblock = { 
				$args[0] | Add-VMHardDiskDrive -Path $args[1]
				$bootOrder = ($args[0] | Get-VMFirmware).Bootorder
				if ($bootOrder[0].BootType -ne 'Drive')
				{
					$args[0] | Set-VMFirmware -FirstBootDevice $args[0].HardDrives[0]
				}
			}
			ArgumentList = $vhd,$vhd.ImagePath
		}
		InvokeHyperVCommand @invParams
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
			$projectRootUnc = ConvertToUncPath -LocalFilePath $script:LabConfiguration.ProjectRootFolder -ComputerName $script:LabConfiguration.HostServer.Name
			Copy-Item -Path "$PSScriptRoot\Convert-WindowsImage.ps1" -Destination $projectRootUnc -Force

			$tempAnswerFile = Copy-Item -Path $AnswerFilePath -Destination $projectRootUnc -Force -PassThru
			$localTempAnswerFilePath = $tempanswerfile.Fullname -replace '.*(\w)\$','$1:'
			
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
				ScriptBlock = $sb
				ArgumentList = (Join-Path -Path $script:LabConfiguration.ProjectRootFolder -ChildPath 'Convert-WindowsImage.ps1'),$IsoFilePath,$SizeBytes,$Edition,$VhdFormat,$VhdPath,$Sizing,$VHDPartitionStyle,$localTempAnswerFilePath
			}
			$result = InvokeHyperVCommand @icmParams
			if ($PassThru.IsPresent) {
				$result
			}
		} catch {
			$PSCmdlet.ThrowTerminatingError($_)
		} finally {
			Remove-Item -Path $tempAnswerFile -ErrorAction Ignore
		}
	}
}
function New-LabVhd
{
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param
	(
		
		[Parameter(Mandatory,ParameterSetName = 'Name')]
		[ValidateNotNullOrEmpty()]
		[string]$Name,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(512MB, 1TB)]
		[int64]$Size = (Invoke-Expression $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Size),
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('Dynamic','Fixed')]
		[string]$Sizing = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Sizing,
	
		[Parameter(Mandatory,ParameterSetName = 'OSInstall')]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ TestIsIsoNameValid $_ })]
		[string]$OperatingSystem,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$PassThru
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{	
			$params = @{
				'SizeBytes' = $Size
			}
			$vhdPath = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Path
			if ($PSBoundParameters.ContainsKey('OperatingSystem'))
			{
				$answerFilePath = (GetUnattendXmlFile -OperatingSystem $OperatingSystem).FullName
				$isoFileName = $script:LabConfiguration.ISOs.where({ $_.Name -eq $OperatingSystem }).FileName
				$cvtParams = $params + @{
					IsoFilePath = Join-Path -Path $script:LabConfiguration.IsoFolderPath -ChildPath $isoFileName
					VhdPath = '{0}.vhdx' -f (Join-Path -Path $vhdPath -ChildPath ($Name -replace ' '))
					VhdFormat = 'VHDX'
					Sizing = $Sizing
					PassThru = $true
					AnswerFilePath = $answerFilePath
				}

				$vhd = ConvertToVirtualDisk @cvtParams
			}
			else
			{
				$params.ComputerName = $script:LabConfiguration.HostServer.Name
				$params.Path = "$vhdPath\$Name.vhdx"
				if ($Sizing -eq 'Dynamic')
				{
					$params.Dynamic = $true
				}
				elseif ($Sizing -eq 'Fixed')
				{
					$params.Fixed = $true
				}

				$invParams = @{
					ScriptBlock = { $params = $args[0]; New-VHD @params }
					ArgumentList = $params
				}
				$vhd = InvokeHyperVCommand @invParams
			}
			if ($PassThru.IsPresent) {
				$vhd
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
			ScriptBlock = { Get-ChildItem -Path $args[0] -File | foreach { Get-VHD -Path $_.FullName } }
			ArgumentList = $defaultVhdPath
		}
		InvokeHyperVCommand @icmParams
	}
	catch
	{
		$PSCmdlet.ThrowTerminatingError($_)
	}
}
function Get-LabVm
{
	[CmdletBinding(DefaultParameterSetName = 'Name')]
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
			ScriptBlock = { $name = $args[0]; @(Get-VM).where({ $_.Name -match $name }) }
			ArgumentList = $nameMatch
		}
		InvokeHyperVCommand @icmParams
	}
	catch
	{
		if ($_.Exception.Message -notmatch 'Hyper-V was unable to find a virtual machine with name') {
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}
function InvokeHyperVCommand
{
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[scriptblock]$Scriptblock,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[object[]]$ArgumentList
	)

	$ErrorActionPreference = 'Stop'

	$icmParams = @{
		ComputerName = $script:LabConfiguration.HostServer.Name
		ScriptBlock = $Scriptblock
		ArgumentList = $ArgumentList
	}
	Invoke-Command @icmParams

}
function New-LabSwitch
{
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Name = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VirtualSwitch.Name,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('Internal','External')]
		[string]$Type = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VirtualSwitch.Type
		
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{
			$scriptBlock = {
				if (-not (Get-VmSwitch -Name $args[0] -SwitchType $args[1] -ErrorAction Ignore)) {
					New-VMSwitch -Name $args[0] -SwitchType $args[1]
				}
			}
			$null = InvokeHyperVCommand -Scriptblock $scriptBlock -ArgumentList $Name,$Type		
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
		@{
			Test = { 
				$validNames = $script:LabConfiguration.ISOs.where({ $_.Type -eq 'OS'}).Name
				$xmlFiles = Get-ChildItem "$PSScriptRoot\AutoUnattend" -Filter '*.xml' -File
				$validxmlFiles = $xmlFiles | Where-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) -in $validNames }
				if (@($validNames).Count -ne @($validXmlFiles).Count) {
					$false
				} else {
					$true
				}

			}
			FailMessage = 'One or more operating systems do not have a unattend.xml file in the AutoAttend folder.'
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
function GetUnattendXmlFile
{
	[OutputType('System.IO.FileInfo')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ TestIsOsNameValid $_ })]
		[string]$OperatingSystem
	)

	$ErrorActionPreference = 'Stop'

	Get-ChildItem -Path "$PSScriptRoot\AutoUnattend" -Filter "$OperatingSystem.xml"

}		
function PrepareUnattendXml
{
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Path,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ProductKey,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$UserName,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$UserPassword
	)

	$ErrorActionPreference = 'Stop'

	## Make a copy of the unattend XML
	$tempUnattend = Copy-Item -Path $Path -Destination "$env:TEMP" -PassThru -Force

	## Prep the XML object
	$unattendText = Get-Content -Path $tempUnattend.FullName -Raw
	$xUnattend = ([xml]$unattendText)
	$ns = New-Object System.Xml.XmlNamespaceManager($xunattend.NameTable)
	$ns.AddNamespace('ns', $xUnattend.DocumentElement.NamespaceURI)

	## Insert the correct product key
	$xUnattend.SelectSingleNode('//ns:ProductKey',$ns).InnerText = $ProductKey
	$xUnattend.Save($tempUnattend.FullName)
	
	## Insert the user name and password
	$userxPaths = '//ns:FullName','//ns:Username','//ns:DisplayName','//ns:Name'
	$userxPaths | foreach {
		$xUnattend.SelectSingleNode($_,$ns).InnerXml = $UserName
	}

	$passXpaths = '//ns:LocalAccounts/ns:LocalAccount/ns:Password/ns:Value'
	$passXPaths | foreach {
		$xUnattend.SelectSingleNode($_,$ns).InnerXml = $UserPassword
	}

	$ns = New-Object System.Xml.XmlNamespaceManager($xunattend.NameTable)
	$ns.AddNamespace('ns', $xUnattend.DocumentElement.NamespaceURI)
	
	,'//ns:Autologon/ns:Password/ns:Value'

	$xUnattend.Save($tempUnattend.FullName)

	## Add the AutoUnattend.xml file to the root of the ISO
	## TODO: I see no way to automate this in PowerShell
	Write-Host "The XML file at [$($tempUnattend.FullName)] is now ready to be added to the ISO."
}