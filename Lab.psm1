#Requires -RunAsAdministrator

#region Configuration
Set-StrictMode -Version Latest

## Change this back to LabConfiguration.psd1
$configFilePath = "$PSScriptRoot\MyLabConfiguration.psd1"
$script:LabConfiguration = Import-PowerShellDataFile -Path $configFilePath

#endregion
function New-Lab {
	[CmdletBinding()]
	param (		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$WinRmCopy
	)
	$ErrorActionPreference = 'Stop'

	try {
		## Create the switch
		NewLabSwitch

		## Create the domain controller
		New-ActiveDirectoryForest
		
		# region Create the member servers
		foreach ($type in $($script:LabConfiguration.VirtualMachines).where($_.Type -ne 'Domain Controller').Type) {
			& "New-$TypeServer"
		}
		#endregion
	} catch {
		Write-Error  "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
	}
}
function New-ActiveDirectoryForest {
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		
	)

	$ErrorActionPreference = 'Stop'

	## Build the VM
	$vm = New-LabVm -ServerType 'Domain Controller' -PassThru

	## Grab config values from file
	$forestConfiguration = $script:LabConfiguration.ActiveDirectoryConfiguration
	$forestParams = @{
		DomainName                    = $forestConfiguration.DomainName
		DomainMode                    = $forestConfiguration.DomainMode
		ForestMode                    = $forestConfiguration.ForestMode
		Confirm                       = $false
		SafeModeAdministratorPassword = (ConvertTo-SecureString -AsPlainText $forestConfiguration.SafeModeAdministratorPassword -Force)
	}
	
	## Build the forest
	Install-ADDSForest @forestParams

	# Install-ADDSDomainController -DomainName test.local -Confirm:$false -InstallDns -SafeModeAdministratorPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force)
	
}
function New-SqlServer {
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	()

	$ErrorActionPreference = 'Stop'

	## Build the VM
	$vm = New-LabVm -ServerType 'SQL' -PassThru
	Install-SqlServer -ComputerName $vm.Name
	
}
function New-WebServer {
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	()

	$ErrorActionPreference = 'Stop'

	## Build the VM
	$vm = New-LabVm -ServerType 'Web' -PassThru
	Install-IIS -ComputerName $vm.Name
	
}
function Install-IIS {
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName
	)

	$ErrorActionPreference = 'Stop'

	$null = InvokeHypervCommand -ScriptBlock { Install-WindowsFeature -Name Web-Server }
	
}
function Install-SqlServer {
	[OutputType([void])]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName
	)
	$ErrorActionPreference = 'Stop'

	$uncProjectFolder = ConvertToUncPath -LocalFilePath $script:LabConfiguration.ProjectRootFolder -ComputerName $script:LabConfiguration.HostServer.Name
	$copiedConfigFile = Copy-Item -Path "$PSScriptRoot\SqlServer.ini" -Destination $uncProjectFolder -PassThru

	$invokeParams = @{
		ComputerName = $ComputerName
		Command      = '{0} /CONFIGURATIONFILE={1}\SqlServer.ini' -f $script:LabConfiguration.SQLServerInstallerPath, $script:LabConfiguration.ProjectRootFolder
	}

	InvokeProgram @invokeParams
	
}
function New-LabVm {
	[OutputType([void])]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('SQL', 'Web', 'Domain Controller')]
		[string]$Type,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$PassThru
	)

	$ErrorActionPreference = 'Stop'

	$name = GetNextLabVmName -Type $Type

	## Create the VM
	$scriptBlock = {
		$vmParams = @{
			Name               = $args[0]
			Path               = $args[1]
			MemoryStartupBytes = $args[2]
			Switch             = $args[3]
			Generation         = $args[4]
		}
		New-VM @vmParams
	}
	$argList = @(
		$name
		$script:LabConfiguration.DefaultVirtualMachineConfiguration.VMConfig.Path
		(Invoke-Expression -Command $script:LabConfiguration.DefaultVirtualMachineConfiguration.VMConfig.StartupMemory)
		(GetLabSwitch).Name
		$script:LabConfiguration.DefaultVirtualMachineConfiguration.VmConfig.Generation
	)
	$vm = InvokeHyperVCommand -Scriptblock $scriptBlock -ArgumentList $argList

	## Create the VHD and install Windows on the VM
	$os = @($script:LabConfiguration.VirtualMachines).where({$_.Type -eq $Type}).OS
	AddOperatingSystem -Vm $vm -OperatingSystem $os

	InvokeHyperVCommand -Scriptblock { Start-Vm -Name $args[0] } -ArgumentList $name
	Wait-Ping -ComputerName $name
	
	if ($PassThru.IsPresent) {
		$vm
	}
	
}
function TestIsIsoNameValid {
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
function TestIsOsNameValid {
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
function AddOperatingSystem {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[object]$Vm,
	
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ TestIsOsNameValid $_ })]
		[string]$OperatingSystem
		
	)

	$ErrorActionPreference = 'Stop'

	try {
		$templateAnswerFilePath = (GetUnattendXmlFile -OperatingSystem $OperatingSystem).FullName
		$isoConfig = $script:LabConfiguration.ISOs.where({$_.Name -eq $OperatingSystem})
		
		$ipAddress = NewVmIpAddress
		$prepParams = @{
			Path         = $templateAnswerFilePath
			VMName       = $vm.Name
			IpAddress    = $ipAddress
			DnsServer    = $script:LabConfiguration.DefaultOperatingSystemConfiguration.Network.DnsServer
			ProductKey   = $isoConfig.ProductKey
			UserName     = $script:LabConfiguration.DefaultOperatingSystemConfiguration.User.Name
			UserPassword = $script:LabConfiguration.DefaultOperatingSystemConfiguration.User.Password
		}
		$answerFile = PrepareUnattendXmlFile @prepParams

		if (-not ($vhd = NewLabVhd -OperatingSystem $OperatingSystem -AnswerFilePath $answerFile.FullName -Name $vm.Name -PassThru)) {
			throw 'VHD creation failed'
		}

		$invParams = @{
			Scriptblock  = {
				$vm = Get-Vm -Name $args[0]
				$vm | Add-VMHardDiskDrive -Path $args[1]
				$bootOrder = ($vm | Get-VMFirmware).Bootorder
				if ($bootOrder[0].BootType -ne 'Drive') {
					$vm | Set-VMFirmware -FirstBootDevice $vm.HardDrives[0]
				}
			}
			ArgumentList = $Vm.Name, $vhd.Path
		}
		InvokeHyperVCommand @invParams

		## Add the VM to the local hosts file
		if (-not (Get-HostsFileEntry | where {$_.HostName -eq $vm.Name})) {
			Add-HostsFileEntry -HostName $vm.Name -IpAddress $ipAddress -ErrorAction Ignore
		}
	} catch {
		$PSCmdlet.ThrowTerminatingError($_)
	}
}
function ConvertToVirtualDisk {
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
		[string]$VHDPartitionStyle = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.PartitionStyle
		
	)

	$ErrorActionPreference = 'Stop'

	$projectRootUnc = ConvertToUncPath -LocalFilePath $script:LabConfiguration.ProjectRootFolder -ComputerName $script:LabConfiguration.HostServer.Name
	Copy-Item -Path "$PSScriptRoot\Convert-WindowsImage.ps1" -Destination $projectRootUnc -Force
		
	## Copy the answer file to the Hyper-V host
	$answerFileName = $AnswerFilePath | Split-Path -Leaf
	Copy-Item -Path $AnswerFilePath -Destination $projectRootUnc -Force
	$localTempAnswerFilePath = Join-Path -Path ($projectrootunc -replace '.*(\w)\$', '$1:') -ChildPath $answerFileName
		
	$sb = {
		. $args[0]
		$convertParams = @{
			SourcePath        = $args[1]
			SizeBytes         = $args[2]
			Edition           = $args[3]
			VHDFormat         = $args[4]
			VHDPath           = $args[5]
			VHDType           = $args[6]
			VHDPartitionStyle = $args[7]
		}
		if ($args[8]) {
			$convertParams.UnattendPath = $args[8]
		}
		Convert-WindowsImage @convertParams
		Get-Vhd -Path $args[5]
	}

	$icmParams = @{
		ScriptBlock  = $sb
		ArgumentList = (Join-Path -Path $script:LabConfiguration.ProjectRootFolder -ChildPath 'Convert-WindowsImage.ps1'), $IsoFilePath, $SizeBytes, $Edition, $VhdFormat, $VhdPath, $Sizing, $VHDPartitionStyle, $localTempAnswerFilePath
	}
	InvokeHyperVCommand @icmParams
}
function NewLabVhd {
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param
	(
		
		[Parameter(Mandatory, ParameterSetName = 'OSInstall')]
		[ValidateNotNullOrEmpty()]
		[string]$Name,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(512MB, 1TB)]
		[int64]$Size = (Invoke-Expression $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Size),
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('Dynamic', 'Fixed')]
		[string]$Sizing = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Sizing,
	
		[Parameter(Mandatory, ParameterSetName = 'OSInstall')]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ TestIsOsNameValid $_ })]
		[string]$OperatingSystem,

		[Parameter(Mandatory, ParameterSetName = 'OSInstall')]
		[ValidateNotNullOrEmpty()]
		[string]$AnswerFilePath,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$PassThru
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try {	
			$params = @{
				'SizeBytes' = $Size
			}
			$vhdPath = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Path
			if ($PSBoundParameters.ContainsKey('OperatingSystem')) {
				$isoFileName = $script:LabConfiguration.ISOs.where({ $_.Name -eq $OperatingSystem }).FileName

				$cvtParams = $params + @{
					IsoFilePath    = Join-Path -Path $script:LabConfiguration.IsoFolderPath -ChildPath $isoFileName
					VhdPath        = '{0}.vhdx' -f (Join-Path -Path $vhdPath -ChildPath $Name)
					VhdFormat      = 'VHDX'
					Sizing         = $Sizing
					AnswerFilePath = $AnswerFilePath
				}
				
				$vhd = ConvertToVirtualDisk @cvtParams
			} else {
				$params.ComputerName = $script:LabConfiguration.HostServer.Name
				$params.Path = "$vhdPath\$Name.vhdx"
				if ($Sizing -eq 'Dynamic') {
					$params.Dynamic = $true
				} elseif ($Sizing -eq 'Fixed') {
					$params.Fixed = $true
				}

				$invParams = @{
					ScriptBlock  = { $params = $args[0]; New-VHD @params }
					ArgumentList = $params
				}
				$vhd = InvokeHyperVCommand @invParams
			}
			if ($PassThru.IsPresent) {
				$vhd
			}
		} catch {
			Write-Error $_.Exception.Message
		}
	}
}
function NewVmIpAddress {
	[OutputType('string')]
	[CmdletBinding()]
	param
	()

	$ipNet = $script:LabConfiguration.DefaultOperatingSystemConfiguration.Network.IpNetwork
	$ipBase = $ipNet -replace ".$($ipNet.Split('.')[-1])$"
	$randomLastOctet = Get-Random -Minimum 10 -Maximum 254
	$ipBase, $randomLastOctet -join '.'
	
}
function Get-LabVhd {
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Name
	
	)
	try {
		$defaultVhdPath = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Path

		$icmParams = @{
			ScriptBlock  = { Get-ChildItem -Path $args[0] -File | foreach { Get-VHD -Path $_.FullName } }
			ArgumentList = $defaultVhdPath
		}
		InvokeHyperVCommand @icmParams
	} catch {
		$PSCmdlet.ThrowTerminatingError($_)
	}
}
function Get-LabVm {
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
	if ($PSBoundParameters.ContainsKey('Name')) {
		$nameMatch = $Name
	} elseif ($PSBoundParameters.ContainsKey('Type')) {
		$nameMatch = $Type
	}

	try {
		$icmParams = @{
			ScriptBlock  = { $name = $args[0]; @(Get-VM).where({ $_.Name -match $name }) }
			ArgumentList = $nameMatch
		}
		InvokeHyperVCommand @icmParams
	} catch {
		if ($_.Exception.Message -notmatch 'Hyper-V was unable to find a virtual machine with name') {
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}
function InvokeHyperVCommand {
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
		ScriptBlock  = $Scriptblock
		ArgumentList = $ArgumentList
	}
	
	if (-not (Get-Variable 'hypervSession' -Scope Script -ErrorAction Ignore)) {
		$script:hypervSession = New-PSSession -ComputerName $script:LabConfiguration.HostServer.Name
	}
	$icmParams.Session = $script:hypervSession
	
	Invoke-Command @icmParams

}
function GetLabSwitch {
	[OutputType('Microsoft.HyperV.PowerShell.VMSwitch')]
	[CmdletBinding()]
	param
	()

	$ErrorActionPreference = 'Stop'

	$switchConfig = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VirtualSwitch

	$scriptBlock = {
		if ($args[1] -eq 'External') {
			Get-VmSwitch -SwitchType 'External'
		} else {
			Get-VmSwitch -Name $args[0] -SwitchType $args[1]
		}
	}
	InvokeHyperVCommand -Scriptblock $scriptBlock -ArgumentList $switchConfig.Name, $switchConfig.Type
}
function NewLabSwitch {
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Name = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VirtualSwitch.Name,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('Internal', 'External')]
		[string]$Type = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VirtualSwitch.Type
		
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try {
			$scriptBlock = {
				if ($args[1] -eq 'External') {
					if ($externalSwitch = Get-VmSwitch -SwitchType 'External') {
						$switchName = $externalSwitch.Name
					} else {
						$switchName = $args[0]
						$netAdapterName = (Get-NetAdapter -Physical| where { $_.Status -eq 'Up' }).Name
						$null = New-VMSwitch -Name $args[0] -NetAdapterName $netAdapterName
					}
				} else {
					$switchName = $args[0]
					if (-not (Get-VmSwitch -Name $args[0] -ErrorAction Ignore)) {
						$null = New-VMSwitch -Name $args[0] -SwitchType $args[1]
					}
				}
			}
			InvokeHyperVCommand -Scriptblock $scriptBlock -ArgumentList $Name, $Type
		} catch {
			Write-Error $_.Exception.Message
		}
	}
}
function ConvertToUncPath {
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
	process {
		try {
			foreach ($Computer in $ComputerName) {
				$RemoteFilePathDrive = ($LocalFilePath | Split-Path -Qualifier).TrimEnd(':')
				"\\$Computer\$RemoteFilePathDrive`$$($LocalFilePath | Split-Path -NoQualifier)"
			}
		} catch {
			Write-Error $_.Exception.Message
		}
	}
}
function GetNextLabVmName {
	[OutputType('string')]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Type
	)

	if (-not ($types = @($script:LabConfiguration.VirtualMachines).where({$_.Type -eq $Type}))) {
		throw "Unrecognize VM type: [$($Type)]"
	}

	if (-not ($highNumberVm = Get-LabVm -Type $Type | Select -ExpandProperty Name | Sort-Object -Descending | Select-Object -First 1)) {
		$nextNum = 1
	} else {
		[int]$highNum = [regex]::matches($highNumberVm, '(\d+)$').Groups[1].Value
		$nextNum = $highNum + 1
	}

	$baseName = $types.BaseName
	
	'{0}{1}' -f $baseName, $nextNum
}
function GetUnattendXmlFile {
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
function PrepareUnattendXmlFile {
	[OutputType('System.IO.FileInfo')]
	[CmdletBinding(SupportsShouldProcess)]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Path,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$VMName,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$IpAddress,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$DnsServer,

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
	$tempUnattend = Copy-Item -Path $Path -Destination $env:TEMP -PassThru -Force

	## Prep the XML object
	$unattendText = Get-Content -Path $tempUnattend.FullName -Raw
	$xUnattend = ([xml]$unattendText)
	$ns = New-Object System.Xml.XmlNamespaceManager($xunattend.NameTable)
	$ns.AddNamespace('ns', $xUnattend.DocumentElement.NamespaceURI)

	## Insert the correct product key
	$xUnattend.SelectSingleNode('//ns:ProductKey', $ns).InnerText = $ProductKey
	
	## Insert the user name and password
	$userxPaths = '//ns:FullName', '//ns:Username', '//ns:DisplayName', '//ns:Name'
	$userxPaths | foreach {
		$xUnattend.SelectSingleNode($_, $ns).InnerXml = $UserName
	}

	$passXpaths = '//ns:LocalAccounts/ns:LocalAccount/ns:Password/ns:Value'
	$passXPaths | foreach {
		$xUnattend.SelectSingleNode($_, $ns).InnerXml = $UserPassword
	}

	$xUnattend.SelectSingleNode('//ns:AutoLogon/ns:Password/ns:Value', $ns).InnerText = $UserPassword

	## Insert the host name
	$xUnattend.SelectSingleNode('//ns:ComputerName', $ns).InnerText = $VMName

	# Insert the NIC configuration
	$xUnattend.SelectSingleNode('//ns:Interface/ns:UnicastIpAddresses/ns:IpAddress', $ns).InnerText = "$IpAddress/24"
	$xUnattend.SelectSingleNode('//ns:DNSServerSearchOrder/ns:IpAddress', $ns).InnerText = $DnsServer

	## Save the config back to the XML file
	$xUnattend.Save($tempUnattend.FullName)

	$tempUnattend
}
function Add-FileToIso {
	[OutputType('void')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$IsoPath,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string[]]$FilePath
	)

	$ErrorActionPreference = 'Stop'
	
	try {
		## Mount the ISO
		$mountedISO = Mount-DiskImage -ImagePath $IsoPath
		$volume = Get-DiskImage -ImagePath $mountedISO.ImagePath | Get-Volume
		
		## Create the temp folder
		$tempFolder = "$env:temp\$((New-Guid).Guid)"
		$tempIsoPath = "$env:temp\$((New-Guid).Guid).iso"
		$null = New-Item -Path $tempFolder -ItemType Directory

		## Copy the ISO contents to the temp folder
		$source = '{0}:\*' -f $volume.DriveLetter
		Copy-Item -Path $source -Destination $tempFolder -Recurse -Force

		## Add files to be in ISO to the temp folder
		Copy-Item -Path $FilePath -Destination $tempFolder

		## Create the new ISO
		$bootData = '2#p0,e,b"{0}"#pEF,e,b"{1}"' -f "$PSScriptRoot\boot-dependencies\etfsboot.com", "$PSScriptRoot\boot-dependencies\efisys.bin"
		$proc = Start-Process -FilePath "$PSScriptRoot\boot-dependencies\oscdimg.exe" -ArgumentList "-bootdata:$BootData", '-u2', '-udfver102', $tempFolder, $tempIsoPath -PassThru -Wait -NoNewWindow
		if ($proc.ExitCode -ne 0) {
			throw "ISO generation failed with exit code [$($proc.ExitCode)]"
		}

		## Remove the original ISO and move the temp ISO to the original's place
		# Remove-Item -Path $IsoPath
		# Move-Item -Path $tempIsoPath -Destination $IsoPath

	} catch {
		$PSCmdlet.ThrowTerminatingError($_)
	} finally {
		Dismount-DiskImage -ImagePath $IsoPath
		Remove-Item -Path $tempFolder -ErrorAction Ignore
	}
}
function Add-HostsFileEntry {
	[CmdletBinding()]
	param
	(
		
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('^[^\.]+$')]
		[string]$HostName,
		
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ipaddress]$IpAddress,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Comment,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName = $env:COMPUTERNAME,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[pscredential]$Credential,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$HostFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"
		
				
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try {
			$IpAddress = $IpAddress.IPAddressToString
			
			$getParams = @{ }
			if ($ComputerName -ne $env:COMPUTERNAME) {
				$getParams.ComputerName = $ComputerName
				$getParams.Credential = $Credential
			}
			
			$existingHostEntries = Get-HostsFileEntry @getParams
			
			if ($result = $existingHostEntries | where HostName -EQ $HostName) {
				throw "The hostname [$($HostName)] already exists in the host file with IP [$($result.IpAddress)]"
			} elseif ($result = $existingHostEntries | where IPAddress -EQ $IpAddress) {
				Write-Warning "The IP address [$($result.IPAddress)] already exists in the host file for the hostname [$($HostName)]. You should probabloy remove the old one hostname reference."
			}
			$vals = @(
				$IpAddress
				$HostName
			)
			if ($PSBoundParameters.ContainsKey('Comment')) {
				$vals += "# $Comment"
			}
			
			$sb = {
				param($HostFilePath, $vals)
				
				## If the hosts file doesn't end with a blank line, make it so
				if ((Get-Content -Path $HostFilePath -Raw) -notmatch '\n$') {
					Add-Content -Path $HostFilePath -Value ''
				}
				Add-Content -Path $HostFilePath -Value ($vals -join "`t")
			}
			
			if ($ComputerName -eq (hostname)) {
				& $sb $HostFilePath $vals
			} else {
				$icmParams = @{
					'ComputerName' = $ComputerName
					'ScriptBlock'  = $sb
					'ArgumentList' = $HostFilePath, $vals
				}
				if ($PSBoundParameters.ContainsKey('Credential')) {
					$icmParams.Credential = $Credential
				}
				[pscustomobject](Invoke-Command @icmParams)
			}
			
			
		} catch {
			Write-Error $_.Exception.Message
		}
	}
}
function Get-HostsFileEntry {
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSCustomObject])]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName = $env:COMPUTERNAME,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[pscredential]$Credential,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$HostFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"
		
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try {
			$sb = {
				param($HostFilePath)
				$regex = '^(?<ipAddress>[0-9.]+)[^\w]*(?<hostname>[^#\W]*)($|[\W]{0,}#\s+(?<comment>.*))'
				$matches = $null
				Get-Content -Path $HostFilePath | foreach {
					$null = $_ -match $regex
					if ($matches) {
						$output = @{
							'IPAddress' = $matches.ipAddress
							'HostName'  = $matches.hostname
						}
						if ('comment' -in $matches.PSObject.Properties.Name) {
							$output.Comment = $matches.comment
						}
						$output
					}
					$matches = $null
				}
			}
			
			if ($ComputerName -eq (hostname)) {
				& $sb $HostFilePath
			} else {
				$icmParams = @{
					'ComputerName' = $ComputerName
					'ScriptBlock'  = $sb
					'ArgumentList' = $HostFilePath
				}
				if ($PSBoundParameters.ContainsKey('Credential')) {
					$icmParams.Credential = $Credential
				}
				[pscustomobject](Invoke-Command @icmParams)
			}
		} catch {
			Write-Error $_.Exception.Message
		}
	}
}
function Remove-HostsFileEntry {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('^[^\.]+$')]
		[string]$HostName,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$HostFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try {
			if (Get-HostsFileEntry | where HostName -EQ $HostName) {
				$regex = "^(?<ipAddress>[0-9.]+)[^\w]*($HostName)(`$|[\W]{0,}#\s+(?<comment>.*))"
				$toremove = (Get-Content -Path $HostFilePath | select-string -Pattern $regex).Line
				## Safer to create a temp file
				$tempFile = [System.IO.Path]::GetTempFileName()
				(Get-Content -Path $HostFilePath | where { $_ -ne $toremove }) | Add-Content -Path $tempFile
				if (Test-Path -Path $tempFile -PathType Leaf) {
					Remove-Item -Path $HostFilePath
					Move-Item -Path $tempFile -Destination $HostFilePath
				}
			} else {
				Write-Warning -Message "No hostname found for [$($HostName)]"
			}
		} catch {
			Write-Error $_.Exception.Message
		}
	}
}
function Set-HostsFileEntry {
	[CmdletBinding()]
	param
	(
		
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try {
				
		} catch {
			Write-Error $_.Exception.Message
		}
	}
}
function Wait-Ping {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$Offline,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(1, [Int64]::MaxValue)]
		[int]$Timeout = 1500
	)

	$ErrorActionPreference = 'Stop'
	try {
		$timer = [Diagnostics.Stopwatch]::StartNew()
		if ($Offline.IsPresent) {
			while ((ping $ComputerName -n 2) -match 'Lost = 0') {
				Write-Verbose -Message "Waiting for [$($ComputerName)] to go offline..."
				if ($timer.Elapsed.TotalSeconds -ge $Timeout) {
					throw "Timeout exceeded. Giving up on [$ComputerName] going offline";
				}
				Start-Sleep -Seconds 10;
			}
		} else {
			## Using good ol' fashioned ping.exe because it just uses ICMP. Test-Connection uses CIM and NetworkInformation.Ping sometimes hangs
			while (-not ((ping $ComputerName -n 2) -match 'Lost = 0')) {
				Write-Verbose -Message "Waiting for [$($ComputerName)] to become pingable..."
				if ($timer.Elapsed.TotalSeconds -ge $Timeout) {
					throw "Timeout exceeded. Giving up on ping availability to [$ComputerName]";
				}
				Start-Sleep -Seconds 10;
			}
		}
	} catch {
		$PSCmdlet.ThrowTerminatingError($_)
	} finally {
		if (Test-Path -Path Variable:\Timer) {
			$timer.Stop();
		}
	}
}